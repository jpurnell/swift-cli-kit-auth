# ``SwiftCLIKitAuth``

Account sign-in for SwiftCLIKit apps, on SwiftIdentity.

## Overview

A sign-in here does three things, and only the last two are this package's: SwiftIdentity's
`Authenticator` decides **who** someone is and **how strongly** that was proven; this package
gathers the credentials, asks the app **whether it admits them**, and holds the session that
follows.

Sources gather credentials through a ``SignInPresenter``, so the same source works in a local
terminal, over SSH, or in a test. A refusal is always ``SignInError/failed``, shown as
"Sign-in failed": the reason goes to SwiftIdentity's audit trail and never to the person signing
in.

## Topics

### Talking to the person

- ``SignInPresenter``
- ``SignInPrompt``
- ``SignInError``

### Gathering credentials

- ``CredentialSource``
- ``PromptedPassword``
- ``PromptedCode``
- ``DeviceSignIn``
- ``DevicePrompt``
- ``Together``
- ``SignInContext``
- ``SourceRequirements``

### Admitting

- ``Admission``
