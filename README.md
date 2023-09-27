# Public Base Rules for YARA in Matrix

These are rules that are considered to be safe to publish to the public. They are not considered to be sensitive in nature and are not considered to be a risk to the organization if they are published.

These rules are made to be used for [Matrix](https://matrix.org) messages in conjunction with the Draupnir Bot and the yara protection.

This repository is following the <https://github.com/CybercentreCanada/CCCS-Yara.git> spec as best as possible.

Additionally there is the `Action` metadata which is used to determine what action to take when a rule matches. The following actions are supported:

- `Notify` - Notify the admins in the admin room about a match
- `RedactAndNotify` - Redact the message and notify the admins in the admin room about a match. In combination with the `NotifcationText` metadata
this also notifies a user in the room about the match with the defined message.
