# BUDLUM AUDIT DIRECTIVE

## 1. Tasks

You work in the Budlum repository. You own all of Budlum. You do all the design. You write all the code. You build every missing part.

Your goal is that Budlum is fully ready for the testnet. You have these tasks.

1. Find every error in the repository.
2. Run Budlum on many operating systems. Ubuntu is one of them. Find every error that each run shows.
3. Build each item that `THE_BUDLUM_DIREKTIF.md` names as necessary for the testnet.
4. Fix every error that you find.

You write the notes and the code in a new pull request.

## 2. Work rules

- Do not ask the user a question. Decide alone.
- If an instruction is not clear, use the most likely meaning. Continue the work.
- Do not stop. Do not wait for approval. Work until the user stops you.
- Do not stop when Budlum seems ready. Keep running, testing and fixing.
- If a tool fails, find another way. Continue the work.
- If you lose context, read the notes in `audit-notes` and continue.
- Check the state of commits, CI runs and pull requests live on GitHub.

## 3. Steps

Do the steps in order.

### Step 1. Make a plan

1. Read the full file tree of the repository.
2. Write a plan as a checklist. The plan lists every directory, module and file that you must inspect.
3. Add the operating systems that you test to the plan. List many systems. Ubuntu is one of them.
4. Create a new branch from `main`.
5. Create the folder `audit-notes` in the branch. Save the plan in `audit-notes/plan.md`.
6. Commit and push the branch. Open a new pull request against `main`.

### Step 2. Read the directive file

1. Search the repository for the file `THE_BUDLUM_DIREKTIF.md`.
2. Read the file in full. Read every line.
3. List each item that the file names as necessary for the testnet.
4. Save the list in `audit-notes/testnet/index.md`.

### Step 3. Audit the repository

1. Inspect every file in the plan. Start at the top of the file tree. End at the bottom.
2. Read every line of every file. Do not skip a file. Do not skip a line.
3. Run the checks that the CI workflows run. Run the security tools of the repository too.
4. Write each error that you find as a finding. Include each failure of a check or a tool. Use the format in Section 4.
5. Fix each error at once. Follow Section 5.
6. Save the findings in `audit-notes/findings`. Use one file for each area of the repository.
7. Mark each file in the plan as done when you finish it.
8. Commit and push after each area.

In each new pass, look for the errors that you missed. Do not write the same finding twice.

### Step 4. Run Budlum on many operating systems

1. Take each operating system in the plan.
2. Get each system with containers, virtual machines or CI runners.
3. On each system, build Budlum. Run Budlum. Run the tests.
4. Write each error of each run as a finding. Use the format in Section 4.
5. Fix each error at once. Follow Section 5.
6. Save the findings in `audit-notes/findings`. Use one file for each operating system.
7. Commit and push after each system.

### Step 5. Build the testnet items

1. Take each item in `audit-notes/testnet/index.md`.
2. Write a full design of the item. Save it in `audit-notes/testnet/<item name>.md`.
3. Write the code of the item. Write the tests of the item.
4. Run the CI checks. Fix each failure at its cause.
5. Commit and push after each item.

Each design has these parts:

- The requirement, as `THE_BUDLUM_DIREKTIF.md` states it.
- What the code does now.
- What is missing or wrong. Link each related finding by its ID.
- The steps to build the item, in order.
- The files, modules and functions that change.
- How to check that the item works.

Write each design in full detail. Update a design when a new finding changes it.

### Step 6. Repeat

1. Remove all marks in the plan.
2. Go back to Step 3.
3. Repeat without end.

## 4. Finding format

Write each finding with these parts:

- ID. Use the form F-0001. Count up by one.
- Location. Give the file path and the line numbers. Quote the faulty lines. For an error of a run, also give the operating system, the command and the output.
- What is wrong. Describe the error.
- Why it is wrong. Give the cause.
- What it causes. Describe every effect.
- How to fix it. Describe the fix in words, step by step.
- Status. Write open or fixed. For fixed, give the commit SHA and the CI run number.

Write each finding in full detail. Leave no detail out. An engineer must be able to fix the error from the note alone.

Check each finding against the live code before you write it.

## 5. Fix rules

- Fix the cause of each error.
- Add or update a test for each fix.
- Run the CI checks after each fix. The CI checks are format, clippy with warnings as errors, and the tests.
- The CI result is the only proof. Do not accept a report from yourself as proof.
- Do not add `allow` or `ignore` markers to pass a check.
- Do not pin an old commit to pass a check.
- Do not make the logic weaker to pass a check.
- After a fix of a run error, run Budlum again on the operating system where the error showed.
- Set a finding to fixed only with the commit SHA and the CI run number.

## 6. Pull request rules

- Use the new pull request for all the notes and all the code. Do not use an existing pull request.
- Use the pull request description as an index of the notes files. Update the index when you add a file.
- Push only to the branch of the new pull request.
- Do not merge the pull request.
- Do not open another pull request or an issue.
- Do not change `THE_BUDLUM_DIREKTIF.md`.

## 7. Writing style

Write all notes in short, plain sentences. Use the present tense. Do not use em dashes.

## 8. Token

A token is on the last line of this file. The token is for this chat only. Use it only for this work.

Do not print the token in a message or a log. Do not write the token in a file that you commit. Do not write it in the pull request text.

Delete the token from every file and document that you write. This directive is your command to do this. Do not wait for another command. Do not ask the user about the token at any time.

Do not commit this directive file.

If the last line says `PASTE_THE_TOKEN_HERE`, no token is given. Continue without a token. Do not ask for one.

PASTE_THE_TOKEN_HERE
