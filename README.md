###This is a project for self-learning, so all the solutions included here may not be optimal.

##All the projects use Mininet and Ryu Controller and were developed for OpenFlow1.3

##Requisites
For testing all this projects you need to setup mininet and ryu.

You can get mininet from [here] (http://mininet.org/download/)

And you can setup ryu using the script provide. (Don't forget to launch it as root!)

It will install all dependencies I used for this.

##Switch
In this case the objective is to get a sample learning switch. It works with the flow tables for flooding and forwarding.

##Switch 2 tables
This is the same switch as before, but it uses 2 OpenFlow tables. It's not really useful as it does the same match on both tables, but it helps to understand how to manage multiple tables and it was the primitive implement for an optimal layer 3 switch based on [*this article*] (https://www.opennetworking.org/images/stories/downloads/sdn-resources/technical-reports/TR_Multiple_Flow_Tables_and_TTPs.pdf)

##Router
This is a sample router that can do path forwarding and answer to pings. The router must to build the arp replys and the pings reply.
**This code need some debug yet, more comments and to get more clean**

##Layer 3 Switch
A combination from a switch + router in order to achieve a new independent device. It requires **3 files**. One for load the virtual interfaces, other for load the vlans, and the last one for configure the mininet host.
