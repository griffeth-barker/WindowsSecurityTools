# WindowsSecurityTools
A small collection of simple scripts to perform common security mitigations in the Windows Server Operating System

## Use Case
These are scripts that I used some years ago to rectify some security vulnerabilities in Windows Servers. I finally sanitzed them and posted them here.

## Getting Started
### Get the Scripts
Clone this repository to the server where you want this script to run:
```
git clone https://github.com/griffeth-barker/WindowsSecurityTools.git
```

### Use the scripts
These scripts can be manually run as one-offs, baked in SCCM, run remotely via tools such as BeyondTrust Remote Support ("canned scripts"), etc. Additionally, they can be called as startup or logon GPOs. There are a variety of ways to utilize these.

That said, it would probably be better to simply set up baselines, managed configurations, profiles, etc. idempotently rather than use these scripts.

## Got Feedback?
Please ⭐star this repository if it is helpful. Constructive feedback is always welcome, as are pull requests. Feel free to open an issue on the repository if needed or [send me a message on Signal](https://griff.systems/signal).
