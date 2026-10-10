"""Unit tests for the exclude matcher, which must agree with rsync.

The hash the matcher computes is compared against the hash a transfer left on
the server, so a pattern that excludes on one side only ships a file without a
redeploy, or redeploys without shipping. These run with no cloud instance.
"""

from pathlib import Path

from deployvm.apps import NPM_JUNK_EXCLUDES, _is_excluded_path


def is_excluded(root: Path, relative: str, exclude: list[str]) -> bool:
    return _is_excluded_path(root / relative, root, exclude)


def test_junk_is_matched_as_a_whole_component(tmp_path):
    assert is_excluded(tmp_path, ".pi/settings.json", NPM_JUNK_EXCLUDES)
    assert is_excluded(tmp_path, "data/.claude/x.json", NPM_JUNK_EXCLUDES)
    assert is_excluded(tmp_path, ".beads/embeddeddolt/db", NPM_JUNK_EXCLUDES)
    # The substring these tokens must not match: rsync ships both of these.
    assert not is_excluded(tmp_path, "src/transform.pipe.ts", NPM_JUNK_EXCLUDES)
    assert not is_excluded(tmp_path, ".pipeline.yml", NPM_JUNK_EXCLUDES)


def test_git_matches_the_directory_and_not_the_prefix(tmp_path):
    assert is_excluded(tmp_path, ".git/config", [".git"])
    assert not is_excluded(tmp_path, ".gitignore", [".git"])
    assert not is_excluded(tmp_path, ".github/workflows/ci.yml", [".git"])


def test_a_slash_anchors_the_pattern_at_the_source_root(tmp_path):
    assert is_excluded(tmp_path, "public/projects/a.png", ["public/projects"])
    assert not is_excluded(
        tmp_path, "other/public/projects/a.png", ["public/projects"]
    )


def test_a_leading_slash_is_anchored_too(tmp_path):
    assert is_excluded(tmp_path, "node_modules/x.js", ["/node_modules"])
    assert not is_excluded(
        tmp_path, "apps/web/node_modules/x.js", ["/node_modules"]
    )


def test_a_glob_matches_the_basename(tmp_path):
    assert is_excluded(tmp_path, ".beads/embeddeddolt/x.gate.lock", ["*.gate.lock*"])
    assert is_excluded(tmp_path, "a/foo.gate.lock.bak", ["*.gate.lock*"])
    assert not is_excluded(tmp_path, "src/main.ts", ["*.gate.lock*"])


def test_an_empty_pattern_excludes_nothing(tmp_path):
    assert not is_excluded(tmp_path, "src/main.ts", [""])


def test_the_npm_lists_agree_on_node_modules(tmp_path):
    # `node_modules` is unanchored in the hash list, so the transfer list must
    # be unanchored too: a nested install would otherwise be hashed but shipped.
    assert is_excluded(tmp_path, "node_modules/x.js", ["node_modules"])
    assert is_excluded(tmp_path, "apps/web/node_modules/x.js", ["node_modules"])


def test_a_leading_slash_anchors_a_glob(tmp_path):
    assert is_excluded(tmp_path, "public/x.png", ["/public/*"])
    assert not is_excluded(tmp_path, "public/deep/x.png", ["/public/*"])
    assert not is_excluded(tmp_path, "other/public/x.png", ["/public/*"])
    assert is_excluded(tmp_path, "public/deep/x.png", ["public/**"])


def test_a_glob_star_does_not_cross_a_slash(tmp_path):
    assert is_excluded(tmp_path, "public/x.png", ["public/*.png"])
    assert not is_excluded(tmp_path, "public/deep/x.png", ["public/*.png"])
    # No slash in the pattern: rsync matches the basename at any depth.
    assert is_excluded(tmp_path, "public/deep/x.png", ["*.png"])
