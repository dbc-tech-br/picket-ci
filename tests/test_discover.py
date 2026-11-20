from picket.discover import SKIP_DIRS, discover, repo_slug


def make_repo(root, name):
    path = root / name
    (path / ".git").mkdir(parents=True)
    return path


def test_discovery_depth_exclusions_and_nested_repos(tmp_path):
    shallow = make_repo(tmp_path, "a")
    nested = make_repo(tmp_path, "group/b")
    make_repo(tmp_path, "a/nested")
    make_repo(tmp_path, "group/deep/c")
    make_repo(tmp_path, "skip-me/repo")
    for name in SKIP_DIRS - {".git"}:
        make_repo(tmp_path, f"{name}/hidden")
    assert discover(tmp_path, 2, ["skip-*"]) == [shallow, nested]
    assert discover(tmp_path, 1, ["skip-*"]) == [shallow]
    assert discover(tmp_path, 0) == []
    assert repo_slug(nested, tmp_path) == "group__b"
    assert repo_slug(shallow) == "a"


def test_root_repo_and_git_file(tmp_path):
    (tmp_path / ".git").write_text("gitdir: /worktree")
    make_repo(tmp_path, "nested")
    assert discover(tmp_path) == [tmp_path]
    assert repo_slug(tmp_path, tmp_path) == tmp_path.name


def test_relative_glob_and_symlinks(tmp_path):
    make_repo(tmp_path, "group/a")
    make_repo(tmp_path, "group/b")
    (tmp_path / "loop").symlink_to(tmp_path, target_is_directory=True)
    assert discover(tmp_path, excludes=["group/*"]) == []
