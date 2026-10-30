#!/bin/sh
set -eu

source_root=$(git rev-parse --show-toplevel)
for variable in $(git rev-parse --local-env-vars); do
    unset "$variable"
done
fixture=$(mktemp -d)
trap 'rm -rf "$fixture"' EXIT HUP INT TERM
export GIT_CONFIG_NOSYSTEM=1
export GIT_CONFIG_GLOBAL=/dev/null
export GIT_CONFIG_COUNT=0
mkdir "$fixture/repo" "$fixture/bin"
cd "$fixture/repo"
git init -q
git config user.name "Hook Test"
git config user.email "hook-test@example.invalid"
git config commit.gpgsign false
mkdir .githooks
cp "$source_root/.githooks/pre-push" .githooks/pre-push
cp "$source_root/.githooks/install.sh" .githooks/install.sh
git add .githooks
git commit -qm "Hook fixture"
previous=$(git rev-parse HEAD)
git commit --allow-empty -qm "Second hook fixture commit"
head=$(git rev-parse HEAD)
zero=0000000000000000000000000000000000000000

cat > "$fixture/bin/make" <<'EOF'
#!/bin/sh
set -eu
test "$#" -eq 1
test "$1" = check
echo check >> "$HOOK_TEST_LOG"
exit "${HOOK_TEST_EXIT:-0}"
EOF
chmod +x "$fixture/bin/make"
export PATH="$fixture/bin:$PATH"
export HOOK_TEST_LOG="$fixture/make.log"

update="refs/heads/test $head refs/heads/test $zero"
run_hook() {
    printf '%s\n' "$1" | .githooks/pre-push
}
expect_failure() {
    if run_hook "$1"; then
        echo "test-hooks: expected hook failure" >&2
        exit 1
    fi
}
expect_calls() {
    test "$(wc -l < "$HOOK_TEST_LOG" | tr -d ' ')" = "$1"
}

# Installation is idempotent and preserves other hook setups.
sh .githooks/install.sh
sh .githooks/install.sh
test "$(git config --local --get core.hooksPath)" = .githooks
git config --local core.hooksPath custom-hooks
if sh .githooks/install.sh; then
    echo "test-hooks: installer overwrote a custom hooksPath" >&2
    exit 1
fi
test "$(git config --local --get core.hooksPath)" = custom-hooks
git config --local core.hooksPath ""
if sh .githooks/install.sh; then
    echo "test-hooks: installer overwrote an explicitly empty hooksPath" >&2
    exit 1
fi
test "$(git config --local --get core.hooksPath)" = ""
git config --local --unset core.hooksPath
mkdir -p .git/hooks
cp .githooks/pre-push .git/hooks/pre-push
if sh .githooks/install.sh; then
    echo "test-hooks: installer replaced an existing hook" >&2
    exit 1
fi
rm .git/hooks/pre-push
cp .githooks/pre-push .git/hooks/pre-commit
if sh .githooks/install.sh; then
    echo "test-hooks: installer hid an existing pre-commit hook" >&2
    exit 1
fi
test -x .git/hooks/pre-commit
if git config --local --get core.hooksPath; then
    echo "test-hooks: failed installation changed core.hooksPath" >&2
    exit 1
fi
rm .git/hooks/pre-commit
chmod -x .githooks/pre-push
# Git Bash filesystems may not support removing executable permission.
if [ ! -x .githooks/pre-push ]; then
    if sh .githooks/install.sh; then
        echo "test-hooks: installer accepted a non-executable pre-push hook" >&2
        exit 1
    fi
fi
chmod +x .githooks/pre-push
sh .githooks/install.sh

run_hook "$update"
expect_calls 1
HOOK_TEST_EXIT=17
export HOOK_TEST_EXIT
if run_hook "$update"; then
    echo "test-hooks: check failure did not block push" >&2
    exit 1
else
    test "$?" -eq 17
fi
expect_calls 2
unset HOOK_TEST_EXIT

printf 'dirty\n' >> .githooks/pre-push
expect_failure "$update"
git restore .githooks/pre-push
printf 'untracked\n' > unexpected.go
expect_failure "$update"
rm unexpected.go
printf 'staged\n' > staged.go
git add staged.go
expect_failure "$update"
git rm -qf staged.go
expect_failure "refs/heads/other $previous refs/heads/other $zero"
expect_failure "$update
refs/heads/other $previous refs/heads/other $zero"
expect_calls 2

git -c tag.gpgsign=false tag -a hook-test -m "Annotated tag fixture"
tag=$(git rev-parse hook-test)
run_hook "refs/tags/hook-test $tag refs/tags/hook-test $zero"
expect_calls 3
run_hook "(delete) $zero refs/heads/old $head"
run_hook ""
expect_calls 3
run_hook "$update
refs/heads/another $head refs/heads/another $zero"
expect_calls 4
run_hook "(delete) $zero refs/heads/old $previous
$update"
expect_calls 5

# Ignored build output is allowed; deletion-only pushes also allow a dirty tree.
printf 'ignored-output\n' >> .git/info/exclude
touch ignored-output
run_hook "$update"
expect_calls 6
touch unexpected.go
run_hook "(delete) $zero refs/heads/old $head"
expect_calls 6
rm unexpected.go

# Linked worktrees share the local setting but use their own checked-out hooks.
git worktree add -q -b linked "$fixture/linked" "$head"
(
    cd "$fixture/linked"
    sh .githooks/install.sh
    run_hook "$update"
)
expect_calls 7

# Exercise Git's real hook invocation and ensure failure prevents remote updates.
git init --bare -q "$fixture/remote.git"
git remote add fixture "$fixture/remote.git"
git push -q fixture HEAD:refs/heads/test
expect_calls 8
HOOK_TEST_EXIT=17
export HOOK_TEST_EXIT
if git push -q fixture HEAD:refs/heads/blocked; then
    echo "test-hooks: Git pushed despite a failed check" >&2
    exit 1
fi
unset HOOK_TEST_EXIT
test -z "$(git ls-remote fixture refs/heads/blocked)"
expect_calls 9
if git push -q fixture "$previous:refs/heads/not-head"; then
    echo "test-hooks: Git pushed a commit other than checked-out HEAD" >&2
    exit 1
fi
test -z "$(git ls-remote fixture refs/heads/not-head)"
expect_calls 9
git push -q fixture :refs/heads/test
expect_calls 9
echo "test-hooks: all checks passed"
