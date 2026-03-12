#!/usr/bin/env python3
"""Domain registration CLI supporting multiple registrar backends.

Providers:
    porkbun  Porkbun API (env: PORKBUN_API_KEY, PORKBUN_SECRET_KEY)
    aws      AWS Route 53 Domains (standard AWS credentials)

Usage:
    rdomain check example.com [--provider aws]
    rdomain register example.com [--provider aws] [--contact contact.json]
    deployvm nameservers example.com --provider vultr | rdomain nameservers example.com
"""

import json
import os
import sys
import urllib.error
import urllib.request
from typing import Any, Literal

from dotenv import load_dotenv

load_dotenv()

import cyclopts
from rich import print

RegistrarName = Literal["porkbun", "aws"]

app = cyclopts.App(name="rdomain", help="Domain registration CLI", sort_key=None)


# --- Porkbun ---

_PB_API = "https://api.porkbun.com/api/json/v3"


def _pb_post(endpoint: str, payload: dict[str, Any]) -> dict[str, Any]:
    url = f"{_PB_API}/{endpoint}"
    data = json.dumps(payload).encode()
    req = urllib.request.Request(url, data=data, headers={"Content-Type": "application/json"})
    try:
        with urllib.request.urlopen(req) as resp:
            return json.loads(resp.read())
    except urllib.error.HTTPError as e:
        body = e.read().decode()
        try:
            return json.loads(body)
        except Exception:
            print(f"[red]HTTP {e.code}: {body}[/red]", file=sys.stderr)
            sys.exit(1)


def _pb_creds() -> tuple[str, str]:
    api_key = os.environ.get("PORKBUN_API_KEY", "")
    secret_key = os.environ.get("PORKBUN_SECRET_KEY", "")
    if not api_key or not secret_key:
        print("[red]Error: PORKBUN_API_KEY and PORKBUN_SECRET_KEY must be set[/red]", file=sys.stderr)
        sys.exit(1)
    result = _pb_post("ping", {"apikey": api_key, "secretapikey": secret_key})
    if result.get("status") != "SUCCESS":
        print(f"[red]Porkbun auth failed: {result.get('message', 'unknown error')}[/red]", file=sys.stderr)
        sys.exit(1)
    return api_key, secret_key


def _pb_check(domain: str) -> tuple[bool, float | None]:
    api_key, secret_key = _pb_creds()
    result = _pb_post(f"domain/check/{domain}", {"apikey": api_key, "secretapikey": secret_key})
    if result.get("status") != "SUCCESS":
        print(f"[red]Error: {result.get('message', 'unknown error')}[/red]", file=sys.stderr)
        sys.exit(1)
    available = result.get("avail") == "yes"
    price_pennies = result.get("price")
    price = int(price_pennies) / 100 if price_pennies is not None else None
    return available, price


def _pb_register(domain: str) -> None:
    api_key, secret_key = _pb_creds()
    check_result = _pb_post(f"domain/check/{domain}", {"apikey": api_key, "secretapikey": secret_key})
    if check_result.get("status") != "SUCCESS":
        print(f"[red]Error: {check_result.get('message', 'unknown error')}[/red]", file=sys.stderr)
        sys.exit(1)
    if check_result.get("avail") != "yes":
        print(f"[red]TAKEN[/red]  '{domain}' is not available", file=sys.stderr)
        sys.exit(1)
    cost = check_result.get("price")
    price = int(cost) / 100 if cost is not None else 0
    print(f"Registering '{domain}' for ${price:.2f}/year...", file=sys.stderr)
    result = _pb_post(f"domain/create/{domain}", {
        "apikey": api_key,
        "secretapikey": secret_key,
        "cost": cost,
        "agreeToTerms": "yes",
    })
    if result.get("status") != "SUCCESS":
        print(f"[red]Error: {result.get('message', 'unknown error')}[/red]", file=sys.stderr)
        sys.exit(1)
    print(f"[green]Registered[/green]  {domain}")
    if "orderId" in result:
        print(f"  Order ID: {result['orderId']}")
    if "balance" in result:
        print(f"  Account balance: ${int(result['balance']) / 100:.2f}")


def _pb_nameservers(domain: str, ns_list: list[str]) -> None:
    api_key, secret_key = _pb_creds()
    result = _pb_post(f"domain/updateNs/{domain}", {
        "apikey": api_key,
        "secretapikey": secret_key,
        "ns": ns_list,
    })
    if result.get("status") != "SUCCESS":
        print(f"[red]Error: {result.get('message', 'unknown error')}[/red]", file=sys.stderr)
        sys.exit(1)


# --- AWS Route 53 Domains ---

def _aws_client(aws_profile: str | None = None):
    import boto3
    from .providers import AWSProvider, check_aws_auth
    aws_config = AWSProvider.get_aws_config(profile=aws_profile)
    check_aws_auth(aws_config.get("profile_name"))
    # Route53 Domains API is only available in us-east-1
    return boto3.Session(**aws_config).client("route53domains", region_name="us-east-1")


def _aws_check(domain: str, aws_profile: str | None = None) -> tuple[bool, float | None]:
    client = _aws_client(aws_profile)
    try:
        result = client.check_domain_availability(DomainName=domain)
    except Exception as e:
        print(f"[red]AWS error: {e}[/red]", file=sys.stderr)
        sys.exit(1)
    available = result["Availability"] == "AVAILABLE"
    price = None
    try:
        tld = domain.split(".", 1)[1]
        prices = client.list_prices(Tld=tld)
        for p in prices.get("Prices", []):
            price = p.get("RegistrationPrice", {}).get("Price")
            break
    except Exception:
        pass
    return available, price


def _aws_register(domain: str, years: int, contact_file: str | None, aws_profile: str | None = None) -> None:
    if not contact_file:
        print("[red]Error: --contact <json-file> is required for AWS registration[/red]", file=sys.stderr)
        print("  Required fields: FirstName, LastName, ContactType, AddressLine1,", file=sys.stderr)
        print("  City, State, CountryCode, ZipCode, PhoneNumber, Email", file=sys.stderr)
        sys.exit(1)
    contact = json.loads(open(contact_file).read())
    client = _aws_client(aws_profile)
    try:
        result = client.register_domain(
            DomainName=domain,
            DurationInYears=years,
            AutoRenew=True,
            AdminContact=contact,
            RegistrantContact=contact,
            TechContact=contact,
            PrivacyProtectAdminContact=True,
            PrivacyProtectRegistrantContact=True,
            PrivacyProtectTechContact=True,
        )
    except Exception as e:
        print(f"[red]AWS error: {e}[/red]", file=sys.stderr)
        sys.exit(1)
    print(f"[green]Registered[/green]  {domain}")
    if "OperationId" in result:
        print(f"  Operation ID: {result['OperationId']}")


def _pb_list() -> list[str]:
    api_key, secret_key = _pb_creds()
    result = _pb_post("domain/listAll", {"apikey": api_key, "secretapikey": secret_key})
    if result.get("status") != "SUCCESS":
        print(f"[red]Error: {result.get('message', 'unknown error')}[/red]", file=sys.stderr)
        sys.exit(1)
    return [d["domain"] for d in result.get("domains", [])]


def _aws_list(aws_profile: str | None = None) -> list[str]:
    client = _aws_client(aws_profile)
    domains = []
    try:
        paginator = client.get_paginator("list_domains")
        for page in paginator.paginate():
            domains.extend(d["DomainName"] for d in page.get("Domains", []))
    except Exception as e:
        print(f"[red]AWS error: {e}[/red]", file=sys.stderr)
        sys.exit(1)
    return domains


def _aws_nameservers(domain: str, ns_list: list[str], aws_profile: str | None = None) -> None:
    client = _aws_client(aws_profile)
    try:
        client.update_domain_nameservers(
            DomainName=domain,
            Nameservers=[{"Name": ns} for ns in ns_list],
        )
    except Exception as e:
        print(f"[red]AWS error: {e}[/red]", file=sys.stderr)
        sys.exit(1)


# --- Commands ---

@app.command
def list(*, provider: RegistrarName = "porkbun", aws_profile: str | None = None):
    """List all registered domains.

    :param provider: Registrar backend (porkbun or aws)
    :param aws_profile: AWS profile name (aws only; falls back to AWS_PROFILE env var)
    """
    domains = _pb_list() if provider == "porkbun" else _aws_list(aws_profile)
    for domain in sorted(domains):
        print(domain)


@app.command
def check(domain: str, *, provider: RegistrarName = "porkbun", aws_profile: str | None = None):
    """Check if a domain is available and show its price.

    :param domain: Domain name to check (e.g., example.com)
    :param provider: Registrar backend (porkbun or aws)
    :param aws_profile: AWS profile name (aws only; falls back to AWS_PROFILE env var)
    """
    if provider == "porkbun":
        available, price = _pb_check(domain)
    else:
        available, price = _aws_check(domain, aws_profile)

    if available:
        print(f"[green]AVAILABLE[/green]  {domain}")
        if price is not None:
            print(f"  Price: ${price:.2f}/year")
    else:
        print(f"[red]TAKEN[/red]  {domain}")


@app.command
def register(
    domain: str,
    *,
    provider: RegistrarName = "porkbun",
    years: int = 1,
    contact: str | None = None,
    aws_profile: str | None = None,
):
    """Register (claim) a domain.

    :param domain: Domain name to register (e.g., example.com)
    :param provider: Registrar backend (porkbun or aws)
    :param years: Registration duration in years (aws only)
    :param contact: Path to JSON file with contact info (aws only)
    :param aws_profile: AWS profile name (aws only; falls back to AWS_PROFILE env var)

    Example (porkbun, no contact file needed)::

        rdomain register example.com

    Example (aws, contact file required)::

        rdomain register example.com --provider aws --contact contact.json

    The contact JSON file must contain::

        {
          "FirstName": "Jane",
          "LastName": "Smith",
          "ContactType": "PERSON",
          "AddressLine1": "123 Main St",
          "City": "Sydney",
          "State": "NSW",
          "CountryCode": "AU",
          "ZipCode": "2000",
          "PhoneNumber": "+61.412345678",
          "Email": "jane@example.com"
        }

    ContactType is one of: PERSON, COMPANY, ASSOCIATION, PUBLIC_BODY, RESELLER
    PhoneNumber format: +<country_code>.<number> (e.g. +1.4155551234)
    """
    if provider == "porkbun":
        _pb_register(domain)
    else:
        _aws_register(domain, years=years, contact_file=contact, aws_profile=aws_profile)


@app.command
def nameservers(domain: str, *, provider: RegistrarName = "porkbun", aws_profile: str | None = None):
    """Set nameservers for a domain, reading a JSON array from stdin.

    :param domain: Domain name (e.g., example.com)
    :param provider: Registrar backend (porkbun or aws)
    :param aws_profile: AWS profile name (aws only; falls back to AWS_PROFILE env var)

    Example:
        echo '["ns1.vultr.com", "ns2.vultr.com"]' | rdomain nameservers example.com
        deployvm nameservers example.com --provider vultr | rdomain nameservers example.com
    """
    raw = sys.stdin.read().strip()
    try:
        ns_list = json.loads(raw)
    except json.JSONDecodeError as e:
        print(f"[red]Error parsing JSON from stdin: {e}[/red]", file=sys.stderr)
        sys.exit(1)

    if not isinstance(ns_list, list) or not all(isinstance(n, str) for n in ns_list):
        print("[red]Error: stdin must be a JSON array of nameserver strings[/red]", file=sys.stderr)
        sys.exit(1)

    if provider == "porkbun":
        _pb_nameservers(domain, ns_list)
    else:
        _aws_nameservers(domain, ns_list, aws_profile)

    print(f"[green]Nameservers updated[/green]  {domain}")
    for ns in ns_list:
        print(f"  {ns}")


if __name__ == "__main__":
    app()
