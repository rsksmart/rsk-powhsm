# powHSM for SGX Setup and onboarding

## Prerequisites

The computer on which the powHSM setup and onboarding is to be executed needs the following installed:

- Docker

## Reminders

- Before running the setup script, make sure that the current user has `sudo` privileges
- Make sure to have the following information at hand:
	- The absolute path where the powHSM is to be installed
	- The pin that will be used to connect to the powHSM

All the items listed above will be required during the setup process, and failing to provide them will result in
the setup script aborting and the entire process will have to be restarted.

## Installation

Unless otherwise specified, all commands are to be executed in the machine in which the powHSM is to be installed.

To setup a brand new powHSM, assuming the powHSM distribution is located in `/path/to/dist` directory, issue:

```
/path/to/dist> sudo ./setup-new-powhsm
```

and follow the instructions provided by the script. The following subsections provide a detailed description of
each step. Experienced users can skip to the [What's next](#whats-next) section.

### Selecting the install directory

The first step is to provide the absolute path to the installation directory:
```
Welcome to the SGX powHSM Setup for RSK 
Enter the absolute path to the installation directory (empty directory name to abort)
> 
```
Make sure to provide the absolute path to an **unexisting** directory. The script will create the specified directory
and will refuse to proceed in case it already exists.

For this example, we will use `/opt/powHSM` as the installation directory, but any valid path can be used. The script
will then require that the path to the installation directory is confirmed:
```
Welcome to the SGX powHSM Setup for RSK 
Enter the absolute path to the installation directory (empty directory name to abort)
> /opt/powHSM
powHSM will be installed to /opt/powHSM
Proceed? [Y/N]
> Y

Installing the powHSM...

Starting the powHSM...
```
Reply with `Y` if the directory is correct and you wish to proceed with the installation. In case the path is incorrect
or you wish to abort the installation, feel free to reply with `N` and start over.

### Onboarding the powHSM

The script will then prompt for a second confirmation before proceeding with the onboarding process:
```
Onboarding the powHSM... 
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
Confirm the onboarding process by replying with `Yes`. The script will then proceed with the onboarding process. At any
time, you can abort the onboarding process by replying with `No`.

The next thing the script will prompt for is the pin for the powHSM. The pin must be composed exactly by 8 alphanumeric
characters, at least one of which must be an alphabetic character. After entering the pin and pressing `Enter`, the
script will proceed with the onboarding process.
```
Please select a pin for the device. The pin must be 8 characters long and contain at least one alphabetic character.
>
Generating a random seed... Seed generated
Onboarding... Onboarded
Disconnecting from HSM... OK
***************
Onboarding done
***************
Onboarding complete.
```

📌 Remember to keep the pin safe, as it will be required in the following steps and by design it will not be recorded at
any of the steps of the setup process.

### Attestation gathering

After completing the onboarding process, the script will proceed with the attestation gathering process. This process
requires restarting the powHSM, and for that reason, the user will be asked to enter the pin again:
```
Gathering attestation
#############################
### -> Get powHSM attestation
#############################
Gathering user-defined attestation value... Using 116dfb22c3bfc58404ded444fac16b7961e6c68b129692b872ac68b31e2c4557 as the user-defined attestation value
Connecting to HSM... OK
Finding mode... Mode: Bootloader
Is device onboarded? ... Onboarded: Yes
Sending echo... Echo OK
Please enter the pin.
> 
```

After entering the correct pin and pressing `Enter`, the script will proceed with the attestation gathering process,
which concludes the installation process.
```
Gathering attestation
#############################
### -> Get powHSM attestation
#############################
Gathering user-defined attestation value... Using 116dfb22c3bfc58404ded444fac16b7961e6c68b129692b872ac68b31e2c4557 as the user-defined attestation value
Connecting to HSM... OK
Finding mode... Mode: Bootloader
Is device onboarded? ... Onboarded: Yes
Sending echo... Echo OK
Please enter the pin.
> 
Unlocking with PIN... PIN accepted
Disconnecting from HSM... OK
Connecting to HSM... OK
Gathering powHSM attestation... powHSM attestation gathered
Parsing the powHSM attestation envelope...
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
################################
### -> Verify powHSM attestation
################################
Attempting to gather root authority from https://certificates.trustedservices.intel.com/Intel_SGX_Provisioning_Certification_RootCA.pem...
Attempting to validate self-signed root authority...
Using https://certificates.trustedservices.intel.com/Intel_SGX_Provisioning_Certification_RootCA.pem as root authority
--------------------------------------------------------------------------------------------
powHSM verified with public keys:
m/44'/0'/0'/0/0:   025fd1ea7ff3b0fea07082942c203da7a7e69d7de53421621139e12ad93c563c9c
m/44'/1'/0'/0/0:   02e4d3fd364d0b1f9cffd6cfd736f3491de343df6f634ebc1f70dff175b700be63
m/44'/1'/1'/0/0:   029d1a5ea03384a35f735d3390de77ab2153d29d14f47b231d65a0d653b4417170
m/44'/1'/2'/0/0:   0397650fb72878e6651a23c384638c25ac8e21052d23c70dd6eb64db8c3234b546
m/44'/137'/0'/0/0: 02d6a13573ad391715751a12e83b391dbf7a237dc5abeb4b708382f106ae40a6f2
m/44'/137'/1'/0/0: 020b792254ba4a31d9bd5eafe8ccef0c53119b248b8f383d41af19619193ce785e
Hash: c010057e43ffd4c1db683b03511c6e06f8b8a73f2d7e8a4fce10f2728707c851

Installed powHSM MRENCLAVE: 72116efdbdf3fdf415eebbded0be15f6e81149ef7adcca36a0108e83b7ac7cb2
Installed powHSM MRSIGNER: dcba724ceb3ce4c93aece10c935eda46d652856dc0c6bf634a8a7961c0e1db68
Installed powHSM version: 5.4
Platform: sgx
UD value: 116dfb22c3bfc58404ded444fac16b7961e6c68b129692b872ac68b31e2c4557
Best block: bdab1b4b4a768d1e32ce538a8121022d93059e467fa834e090db1f2c0db00523
Last transaction signed: 0000000000000000
Timestamp: 0
--------------------------------------------------------------------------------------------

Stopping the powHSM...

powHSM Setup complete. Find the installation in /opt/powHSM.
```

Once that step is finished, all the files required by the powHSM will be located in the installation directory:
```
/opt/powHSM/
├── bin
│   ├── Dockerfile
│   ├── hsmsgx
│   ├── hsmsgx_enclave.signed
│   ├── start
│   └── stop
├── kvstore-nvmem-bcstate.dat
├── kvstore-nvmem-bcstate_updating.dat
├── kvstore-password.dat
├── kvstore-retries.dat
└── kvstore-seed.dat
```

### powHSM service setup
Once installation is complete, the script will proceed with the setup of the powHSM service. The powHSM application
is installed as a `systemd` service. The last piece of information required by the script is the name of the docker
network to which the container running the powHSM will be connected. The default value `net_sgx` is suitable for most
cases, but the user is free to choose a different name. Just pressing `Enter` will use the default value:
```
Creating hsm user and group...
Enter the name of the docker network to be created: [net_sgx]
>
```

The user will be required to confirm the creation of the docker network:
```
The docker network will be named 'net_sgx'. Proceed? [Y/n]
> Y
```

After confirming the creation of the docker network, the script will proceed with the setup of the powHSM service. All
the following steps are automated and require no user intervention:
```
Creating net_sgx network...
Setting permisions...
Creating service...
Enabling service...
EStarting service...
Service started.
To check the status of the service, run 'systemctl status hsmsgx.service'.
HSM SGX setup done.
```

### Verifying the service status

Once the service is properly set up, the user can verify its status by running:
```
systemctl status hsmsgx.service
```

The output should be similar to:
```
● hsmsgx.service - SGX powHSM
     Loaded: loaded (/etc/systemd/system/hsmsgx.service; enabled; vendor preset: enabled)
     Active: active (running) since Wed 2025-01-22 18:58:29 UTC; 6min ago
   Main PID: 2011886 (start)
      Tasks: 7 (limit: 9455)
     Memory: 12.7M
     CGroup: /system.slice/hsmsgx.service
             ├─2011886 /bin/bash /opt/powHSM/bin/start
             └─2011983 docker run --rm --name powhsmsgx-runner --user 996:996 -v /opt/powHSM:/hsm --hostname SGX --net>

Jan 22 18:58:31 sgxhsm01 start[2011983]: [Enclave] Seed loaded
Jan 22 18:58:31 sgxhsm01 start[2011983]: [Enclave] Attestation module initialized
Jan 22 18:58:31 sgxhsm01 start[2011983]: [Enclave] Loading NVM blocks...
Jan 22 18:58:31 sgxhsm01 start[2011983]: [Enclave] Attempting determine secret existence for <nvmem-bcstate>...
Jan 22 18:58:31 sgxhsm01 start[2011983]: [Enclave] Attempting to read secret for <nvmem-bcstate>...
Jan 22 18:58:31 sgxhsm01 start[2011983]: [Enclave] Attempting determine secret existence for <nvmem-bcstate_updating>...
Jan 22 18:58:31 sgxhsm01 start[2011983]: [Enclave] Attempting to read secret for <nvmem-bcstate_updating>...
Jan 22 18:58:31 sgxhsm01 start[2011983]: [Enclave] Modules initialized
Jan 22 18:58:31 sgxhsm01 start[2011983]: [Enclave] Initializing powHSM...
Jan 22 18:58:31 sgxhsm01 start[2011983]: [Enclave] powHSM initialized
```

### Accessing the logs

At any time, the logs of the powHSM service can be accessed by running:
```
journalctl -u hsmsgx.service
```

## What's next

Once the powHSM service is installed and onboarded, it is ready to be used with the powHSM middleware.
Please refer to the [powpeg-node-setup documentation](https://github.com/rootstock/powpeg-node-setup/blob/main/README.md)
for further information on how to properly run the middleware along with the other services that compose the powPeg node.
