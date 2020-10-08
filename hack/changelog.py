#!/usr/bin/env python3

import argparse
import re
from subprocess import Popen, PIPE
import sys
from github import Github

# Generate a changelog from github commit history (pull request merges)

class ChangelogGenerator:
    def __init__(self, github_repo, token):
        self._github = Github(token)
        self._github_repo = self._github.get_repo(github_repo)

    def generate(self, pr_id):
        pr = self._github_repo.get_pull(pr_id)
        return f'{pr.title} ([#{pr_id}]({pr.html_url}), @{pr.user.login})'

def git_log(range=''):
    process = Popen(['git', 'log', range], stdout=PIPE, stderr=PIPE)
    stdout, stderr = process.communicate()
    if process.returncode != 0:
        raise RuntimeError(f'git log returned {process.returncode} and failed with error: {stderr.decode("utf-8")}')
    return stdout.decode("utf-8")

if __name__ == '__main__':
    parser = argparse.ArgumentParser(prog='changelog')
    parser.add_argument('--token', help='Your github token.')
    parser.add_argument('--changelog-file', help='The path to the changelog output file.')
    parser.add_argument('--print-only', action='store_true', help='Only print the output.')
    parser.add_argument('--range', help='The range of commit logs to inspect in the repository.  You can (and should) use tags here.  Example: v5..v10 (This argument is passed to git log, so read the git log documentation for clarification.')
    parser.add_argument('--section-title', help='The title for the section in the changelog that is generated')
    args = parser.parse_args()

    if args.section_title is None:
        print('--section-title is required')
        sys.exit(1)
    if args.token is None:
        print('--token is required')
        sys.exit(1)
    if args.range is None:
        print('--range is required')
        sys.exit(1)
    if args.changelog_file is None and args.print_only is None:
        print('Either --print-only or --changelog-file is required.')
        sys.exit(1)

    logs = git_log(args.range)

    changelog = f'{args.section_title}\n'
    g = ChangelogGenerator('kubernetes-sigs/aws-iam-authenticator', args.token)
    for pr_match in re.finditer(r'Merge pull request #(\d+)', logs):
        pr_id = int(pr_match.group(1))
        changelog += f'* {g.generate(pr_id)}\n'

    if args.print_only:
        print(changelog)
        sys.exit(0)
    else:
        with open(args.changelog_file, 'r+') as f:
            existing = f.read()
            f.write(changelog)
            f.write(existing)
