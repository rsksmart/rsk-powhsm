# powHSM for Ledger Nano S Setup and onboarding

## Prerequisites

The computer on which the powHSM setup and onboarding is to be executed needs the following installed:

- Docker

## Scripts

This can be used to setup a new device as well as to upgrade a device with powHSM to a newer Signer version.

### Setup a new device

To setup a brand new device, first make sure the Ledger Nano S is connected to the machine via USB and in
**Recovery Mode**. For more information on how to do this please refer to
[Ledger Nano S User Manual](https://support.ledger.com/article/360007061974-zd).

Then, to execute the setup process, within the `/path/to/dist` directory, issue:

```
/path/to/dist> ./setup-new-device
```

and follow the instructions. The following subsections provide a detailed description of
each step. Experienced users can skip to the [What's next](#whats-next) section.

#### Install the Signer and UI apps

The first step will install the Signer and UI apps on the Ledger Nano S device. Before doing that, the user is
required to confirm that the device is connected and ready:
```
Welcome to the Ledger Nano S powHSM Setup for RSK 

Connect your ledger into recovery mode:
Connect it while keeping the right button pressed until you see a Recovery message, then
release the right button and wait until the menu appears.
Press [Enter] to continue
```

Pressing `Enter` will proceed with the installation. Pay attention to the instructions both on the terminal and on the device's screen, since a few confirmations are required.
```
Removing the Bitcoin App...
The Ledger will prompt for 'Allow Unknown Manager'. Please accept it.
If the Ledger prompts for 'Remove app' followed by the app name and identifier, then please accept it.
Removing the Ethereum App...
If the Ledger prompts for 'Remove app' followed by the app name and identifier, then please accept it.
Removing the Fido App...
If the Ledger prompts for 'Remove app' followed by the app name and identifier, then please accept it.
Removing the existing certification authority (if any)...
If the Ledger prompts for 'Revoke certificate' followed by the certificate name and its public key, then please accept it.

Setting up the RSK certification authority...
The Ledger will prompt for 'Trust certificate' followed by the certificate name and its public key. Please accept it.

Installing the RSK Signer App...
Installing the RSK UI...

App installation complete. Please disconnect and reconnect the device.
You should see a white screen upon restart.
Press [Enter] to continue
```

#### Onboard the device

Once the apps are installed, the user is instructed to disconnect and reconnect the device. Please note that this time
the device should **NOT** be in Recovery Mode. After reconnecting the device screen should be completely white. Press
`Enter` to proceed to onboarding:
```
Onboarding the device... 
#######################################
### -> Onboarding and attestation setup
#######################################
Connecting to HSM... OK
Finding mode... Mode: Bootloader
Sending echo... Echo OK
Is device onboarded? ... Onboarded: No
************************************************
The following operation will onboard the device.
Do you want to proceed? Yes/No
************************************************
> 
```

After pressing `Enter`, the user is prompted to confirm the onboarding process. Type `Yes` to confirm and the script
will require a pin to be set on the device. The pin must be 8 characters long and contain at least one alphabetic
character. After entering a valid pin, the onboarding process will proceed and the seed will be generated:
```
***********************************************
The following operation will onboard the device.
Do you want to proceed? Yes/No
************************************************
> Yes
Please select a pin for the device. The pin must be 8 characters long and contain at least one alphabetic character.
> 
Generating a random seed... Seed generated
Onboarding... Onboarded
Disconnecting from HSM... OK
*********************************************************************************
Onboarding done
Please disconnect and re-connect the ledger to proceed with the attestation setup
Press [Enter] to continue
*********************************************************************************
```

Once again, disconnect and reconnect the device before pressing `Enter` to proceed with the attestation setup.

#### Attestation setup

After reconnecting the device and pressing `Enter` to continue, the user is once again prompted to enter the pin.
After entering the pin, the attestation setup will proceed and an attestation certificate will be generated:
```
Connecting to HSM... OK
Finding mode... Mode: Bootloader
Is device onboarded? ... Onboarded: Yes
Sending echo... Echo OK
Please enter the pin.
> 
Unlocking with PIN... PIN accepted
Exiting to menu/app (execute signer: No)... Exit OK
Disconnecting from HSM... OK
Connecting to HSM... OK
Handshaking... Handshaking done
Gathering device key... Device key gathered
Setting up the attestation key... Attestation key setup complete
Disconnecting from HSM... OK
Generating the attestation certificate... Attestation certificate saved to /setup/export/device_attestation.json
****************************************************************
Onboarding and attestation setup done
Please disconnect and re-connect the ledger before the first use
****************************************************************

Onboarding complete. Please disconnect and reconnect the device.
Press [Enter] to continue
```

#### Gathering attestation

The final step is to gather the UI and Signer attestations. After reconnecting the device and pressing `Enter`, the
user is prompted to enter the pin once again. After entering the pin, the UI and Signer attestations will be gathered:

```
Gathering attestation
#####################################
### -> Get UI and Signer attestations
#####################################
Gathering user-defined attestation value... Using 8f568f6d7676b41e2fcbb1fdb24801bb2db5596732b1d286debc92e084aed605 as the user-defined attestation value
Connecting to HSM... OK
Finding mode... Mode: Bootloader
Is device onboarded? ... Onboarded: Yes
Sending echo... Echo OK
Please enter the pin.
> 
Unlocking with PIN... PIN accepted
Disconnecting from HSM... OK
Connecting to HSM... OK
Gathering UI attestation... UI attestation gathered
Exiting UI... Exit OK
Disconnecting from HSM... OK
Connecting to HSM... OK
Gathering Signer attestation... Signer attestation gathered
Generating the attestation certificate... Attestation certificate saved to /setup/export/attestation.json

Gathering public keys
### -> Get public keys
Connecting to HSM... OK
Finding mode... Mode: Signer
Getting public key for path 'btc'... OK
Getting public key for path 'rsk'... OK
Getting public key for path 'mst'... OK
Getting public key for path 'tbtc'... OK
Getting public key for path 'trsk'... OK
Getting public key for path 'tmst'... OK
Public keys saved to /setup/export/public-keys.txt
JSON-formatted public keys saved to /setup/export/public-keys.json
Disconnecting from HSM... OK

Verifying attestation
########################################
### -> Verify UI and Signer attestations
########################################
Using 0490f5c9d15a0134bb019d2afd0bf297149738459706e7ac5be4abc350a1f818057224fce12ec9a65de18ec34d6e8c24db927835ea1692b14c32e9836a75dad609 as root authority
--------------------------------------------------------------------------------------------------------
UI verified with:
UD value: 8f568f6d7676b41e2fcbb1fdb24801bb2db5596732b1d286debc92e084aed605
Derived public key (m/44'/0'/0'/0/0): 02b904c01347f9f3b9a006fc006f828fb01a3652f1d0de82f7d052b82a3de42c85
Authorized signer hash: 0be4467d4996925ee81a33f9217cce1d6d834ab54b641846fdec5ba4777498a7
Authorized signer iteration: 1
Installed UI hash: 742a039d07107e0d0f0706ac22d003e42e4de355f3eb089eebe74d42326365a3
Installed UI version: 5.3
--------------------------------------------------------------------------------------------------------
---------------------------------------------------------------------------------------
Signer verified with public keys:
m/44'/0'/0'/0/0:   02b904c01347f9f3b9a006fc006f828fb01a3652f1d0de82f7d052b82a3de42c85
m/44'/1'/0'/0/0:   0268d3a4a92c43323bd51b60c7be6d80f9d9fb8395c26342fad091ef6bec4f2284
m/44'/1'/1'/0/0:   03d35f65ee271b4992c8f259c4e20f2d03535758f41d639dab6427704d67869669
m/44'/1'/2'/0/0:   025ea057514fb0345bca0ae7ef0e1792be1b48d24bb3ade9b8cfbd153046cc6465
m/44'/137'/0'/0/0: 03ceabb7139c36a88197dd966eaeb6c7867f28cb835d6296bcf726ec18053ba4fd
m/44'/137'/1'/0/0: 027068a536213b6dab5013987b8be86a404be420ed1f8dfd1725fa503b1ad4dd79
Hash: d0856a7195b19283240296d036d919aecb8e7b91e2019fffae27843e2465e75f

Installed Signer hash: 0be4467d4996925ee81a33f9217cce1d6d834ab54b641846fdec5ba4777498a7
Installed Signer version: 5.4
Platform: led
UD value: 8f568f6d7676b41e2fcbb1fdb24801bb2db5596732b1d286debc92e084aed605
Best block: e108960a242ad7bd45c21aff9c7ed9c516789e9cffacdd895502727d8f460d2c
Last transaction signed: 0000000000000000
Timestamp: 0
---------------------------------------------------------------------------------------

powHSM Setup complete.
Please disconnect the device.
```

After this step, the device is ready to be used with the powHSM middleware. Refer to the [What's next](#whats-next)
section for further instructions.

### Upgrade an existing device

To upgrade an existing powHSM device to a newer firmware version, you will first need:

- A file `/path/to/dist/pin.txt` with the current device's pin.
- A file `/path/to/dist/device_attestation.json` with the device attestation generated upon setup.
- A fully signed `/path/to/dist/firmware/signer_auth.json`, authorising the signer version to which the device is to be upgraded. 

Then, to execute the upgrade process, within the `/path/to/dist` directory, issue:

```
/path/to/dist> ./upgrade-existing-device
```

and follow the instructions:

#### Connect the device

First connect the Ledger Nano S device to the machine via USB normally (**NOT** in Recovery Mode). Once the device is connected, press `Enter` to proceed:

```
Welcome to the Ledger Nano S powHSM Upgrade for RSK 
Please make sure your HSM is onboarded before continuing with the firmware upgrade.

Connect your ledger.
Press [Enter] to continue
```

#### Authorize the new Signer App

After pressing `Enter`, the upgrade script will authorise the new Signer app and install it on the device. Once this
is done, the user will be prompted to disconnect and reconnect the device:

```
Authorising the new RSK Signer App...
#######################
### -> Authorize signer
#######################
Connecting to HSM... OK
Finding mode... Mode: Bootloader
Is device onboarded? ... Onboarded: Yes
Sending echo... Echo OK
Unlocking with PIN... PIN accepted
Disconnecting from HSM... OK
Authorising signer... Connecting to HSM... OK
Disconnecting from HSM... OK
Signer authorized
#############
### -> Unlock
#############
Connecting to HSM... OK
Finding mode... Mode: Bootloader
Is device onboarded? ... Onboarded: Yes
Sending echo... Echo OK
Unlocking with PIN... PIN accepted
Exiting to menu/app (execute signer: No)... Exit OK
Disconnecting from HSM... OK

Removing the old RSK Signer App...
Installing the new RSK Signer App...

App upgrade complete. Please disconnect and reconnect the device.
Press [Enter] to continue
```

#### Gathering Attestation

After disconnecting and reconnecting the device, just press `Enter` to proceed with the attestation gathering:

```
Gathering attestation
#####################################
### -> Get UI and Signer attestations
#####################################
Gathering user-defined attestation value... Using 22c47f7582cf5b7ac7c57d12e29d89bd0e9178184907065fcc6bf155a6fe4cff as the user-defined attestation value
Connecting to HSM... OK
Finding mode... Mode: Bootloader
Is device onboarded? ... Onboarded: Yes
Sending echo... Echo OK
Unlocking with PIN... PIN accepted
Disconnecting from HSM... OK
Connecting to HSM... OK
Gathering UI attestation... UI attestation gathered
Exiting UI... Exit OK
Disconnecting from HSM... OK
Connecting to HSM... OK
Gathering Signer attestation... Signer attestation gathered
Generating the attestation certificate... Attestation certificate saved to /setup/export/attestation.json

Gathering public keys
### -> Get public keys
Connecting to HSM... OK
Finding mode... Mode: Signer
Getting public key for path 'btc'... OK
Getting public key for path 'rsk'... OK
Getting public key for path 'mst'... OK
Getting public key for path 'tbtc'... OK
Getting public key for path 'trsk'... OK
Getting public key for path 'tmst'... OK
Public keys saved to /setup/export/public-keys.txt
JSON-formatted public keys saved to /setup/export/public-keys.json
Disconnecting from HSM... OK

Verifying attestation
########################################
### -> Verify UI and Signer attestations
########################################
Using 0490f5c9d15a0134bb019d2afd0bf297149738459706e7ac5be4abc350a1f818057224fce12ec9a65de18ec34d6e8c24db927835ea1692b14c32e9836a75dad609 as root authority
--------------------------------------------------------------------------------------------------------
UI verified with:
UD value: 22c47f7582cf5b7ac7c57d12e29d89bd0e9178184907065fcc6bf155a6fe4cff
Derived public key (m/44'/0'/0'/0/0): 02b904c01347f9f3b9a006fc006f828fb01a3652f1d0de82f7d052b82a3de42c85
Authorized signer hash: 0be4467d4996925ee81a33f9217cce1d6d834ab54b641846fdec5ba4777498a7
Authorized signer iteration: 2
Installed UI hash: 742a039d07107e0d0f0706ac22d003e42e4de355f3eb089eebe74d42326365a3
Installed UI version: 5.3
--------------------------------------------------------------------------------------------------------
---------------------------------------------------------------------------------------
Signer verified with public keys:
m/44'/0'/0'/0/0:   02b904c01347f9f3b9a006fc006f828fb01a3652f1d0de82f7d052b82a3de42c85
m/44'/1'/0'/0/0:   0268d3a4a92c43323bd51b60c7be6d80f9d9fb8395c26342fad091ef6bec4f2284
m/44'/1'/1'/0/0:   03d35f65ee271b4992c8f259c4e20f2d03535758f41d639dab6427704d67869669
m/44'/1'/2'/0/0:   025ea057514fb0345bca0ae7ef0e1792be1b48d24bb3ade9b8cfbd153046cc6465
m/44'/137'/0'/0/0: 03ceabb7139c36a88197dd966eaeb6c7867f28cb835d6296bcf726ec18053ba4fd
m/44'/137'/1'/0/0: 027068a536213b6dab5013987b8be86a404be420ed1f8dfd1725fa503b1ad4dd79
Hash: d0856a7195b19283240296d036d919aecb8e7b91e2019fffae27843e2465e75f

Installed Signer hash: 0be4467d4996925ee81a33f9217cce1d6d834ab54b641846fdec5ba4777498a7
Installed Signer version: 5.4
Platform: led
UD value: 22c47f7582cf5b7ac7c57d12e29d89bd0e9178184907065fcc6bf155a6fe4cff
Best block: e108960a242ad7bd45c21aff9c7ed9c516789e9cffacdd895502727d8f460d2c
Last transaction signed: 0000000000000000
Timestamp: 0
---------------------------------------------------------------------------------------

powHSM Upgrade complete.
Please disconnect the device.
```

This concludes the upgrade process. The device is now ready to be used with the powHSM middleware. Refer to the
[What's next](#whats-next) section for further instructions.

## What's next

Once the powHSM device is properly setup and onboarded, it is ready to be used with the powHSM middleware.

## Troubleshooting

This section lists some common issues that might arise during the setup and onboarding
process and provides guidance on how to solve them.

### Ledger Nano S screen is too dim

Unfortunately, it is a well known problem that after a long time of usage, the
Nano S screen might start dimming, eventually reaching a point where it is
nearly impossible to read the on-screen instructions. This is a hardware problem and there are
some workarounds offered both by [Ledger](https://support.ledger.com/article/360021124674-zd)
and [third-party websites](https://symetronix.com/ledger-nano-s-screen-not-working-comprehensive-guide-to-fix-the-issue/). 
In any case, it is still possible to perform the process described in this document,
even if the screen is completely unreadable. This section lists detailed steps so
that the onboarding can be performed even without the possibility of reading any
of the on-screen instructions.

For the update process, there's no need for the user to do anything besides plugging
and unplugging the device when prompted.

#### Detailed steps for onboarding a new device

This step is needed to onboard a new device. To access the Recovery Mode, follow
the steps below:

1. Press and hold the Right button on the Nano S. This is the button furthest
   from the USB port. Keep it pressed while you connect the USB cable to the computer.
   After connecting the cable, keep the button pressed for another 5 seconds, and then
   release it. Wait for another 5 seconds before proceeding to the next step.

   The next step to be performed depends on whether or not the device has a pin set:

   - If the target device has already been onboarded, and has a pin set, proceed to step 2.
   - If the target device has already been onboarded, but has been wiped (i.e.,
   the wrong pin was entered three times in a row), skip step 2 and proceed directly to step 3.
   - If the target device is brand new, skip step 2 and proceed directly to step 3.

2. Note: this step is only required for devices that have already been onboarded
   and have a pin set. If this is not the case, skip to step 3 (see note above).
   To wipe the device, we need to provide the wrong pin three times in a row. To
   do this, follow the exact sequence of button presses below:

   - Press both buttons at the same time, do this 7 times in sequence.
   - Repeat the sequence above on more time, i.e., press both buttons at the same
     time 7 times in sequence.
   - Now press both buttons at the same time exactly 12 times in sequence.

   The device will now be wiped and in Recovery Mode. **Do not unplug the device**
   and proceed to step 3.

3. After the device is in Recovery Mode, it is ready for the onboarding process.
   To start the onboarding, issue the following command in the terminal:

   ```bash
   /path/to/dist> ./setup-new-device
   ```

   You will see the output:

   ```
   Welcome to the Ledger Nano S powHSM Setup for RSK 

   Connect your ledger into recovery mode:
   Connect it while keeping the right button pressed until you see a Recovery message, then
   release the right button and wait until the menu appears.
   Press [Enter] to continue
   ```

4. Press `Enter` to proceed with the onboarding process. The next steps of the
   onboarding will require the user to interact with the device. At any point
   that the script stops and requests the user to Accept an action, the user
   must press the Right button once to confirm the action.

   The first confirmation required is to allow the powHSM manager to access the
   device. The script will stop at this point and the following message will be
   displayed:

   ```
   Removing the Bitcoin App...
   The Ledger will prompt for 'Allow Unknown Manager'. Please accept it.
   If the Ledger prompts for 'Remove app' followed by the app name and identifier, then please accept it.
   ```

   Press the Right button once to confirm access to the manager. If new messages
   are displayed in the console, proceed to step 5. Otherwise, it means you need
   to confirm the removal of the Bitcoin app. In this case, press the Right button
   once more to confirm the removal.

5. The next confirmations will depend on the apps that are currently installed on
   the device. The script will guide you through the process. All the steps below
   will be performed automatically if there's no action needed from the user. At any
   point that the script stops and requests the user to Accept an action, just press
   the Right button once to confirm:

   ```
   Removing the Ethereum App...
   If the Ledger prompts for 'Remove app' followed by the app name and identifier, then please accept it.
   Removing the Fido App...
   If the Ledger prompts for 'Remove app' followed by the app name and identifier, then please accept it.
   Removing the RSK Signer App...
   If the Ledger prompts for 'Remove app' followed by the app name and identifier, then please accept it.
   Removing the RSK UI...
   If the Ledger prompts for 'Remove app' followed by the app name and identifier, then please accept it.
   ```

6. Finally, the script will set up the RSK certification authority. The user will
   be prompted to confirm that the existing certificate should be removed, and then
   to trust the new certificate. In both cases, just press the Right button once to
   confirm:

   ```
   Removing the existing certification authority (if any)...
   If the Ledger prompts for 'Revoke certificate' followed by the certificate name and its public key, then please accept it.

   Setting up the RSK certification authority...
   The Ledger will prompt for 'Trust certificate' followed by the certificate name and its public key. Please accept it.
   ```

   Press the Right button once for each of the confirmations requested.

7. The script will continue installing the apps and should only stop at the
   following step:

   ```
   Installing the RSK Signer App...
   Installing the RSK UI...

   App installation complete. Please disconnect and reconnect the device.
   You should see a white screen upon restart.
   Press [Enter] to continue
   ```

8. After this point, all the information required to perform the onboarding is
   provided by the script. The following steps are listed in the [Onboard the device](#onboard-the-device)
   section of this document.

