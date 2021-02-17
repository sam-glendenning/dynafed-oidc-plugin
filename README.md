# dynafed-oidc-plugin
An authorisation plugin and config manager for the IRIS DynaFed project that allows for permissions to access resources to be determined by attributes from an access token received from an IRIS IAM OIDC IdP.

## Installation
Refer to the [installation instructions](https://wiki.e-science.cclrc.ac.uk/web1/bin/view/EScienceInternal/IRISDynaFedInstallation) on the Twiki.

## Authorisation
The plugin receives information on the user's request for every bucket and object they navigate to in DynaFed. This includes information about the user obtained from their IRIS IAM account. The most important of these is their group membership: IRIS DynaFed assigns buckets to groups. If the user is a member of an IAM group, they may access that group's buckets on DynaFed and import/remove buckets of their own to share with their fellow group members.

## Config Management
The new DynaFed system is much more dynamic than before. It allows for users to dynamically add and remove buckets to the system, creating a more flexible system that requires no admin interference. This requires scripts for managing config files. These config files are then synchronised with other DynaFed hosts to allow for redundancy and globalisation. All of this can be called through the front-end web interface.

### More information?
Visit the [Twiki page](https://wiki.e-science.cclrc.ac.uk/web1/bin/view/EScienceInternal/IRISDynaFed) to learn more in-depth.
Visit the [help page](https://dynafed.stfc.ac.uk/help) for general usage.