.. _rpl-node-sample:

RPL node
###########

Overview
********

A simple RPL node showing how to join in RPL mesh network.

This demo assumes that the platform of choice has networking support,
some adjustments to the configuration may be needed.

The sample will listen for RPL multicast messages and joins with RPL
Border Router node in DAG network. It exposes few resources through
CoAP server role.

The sample exports the following resources:

.. code-block:: none

   /led
   /ipv6/neighbors
   /rpl-info
   /rpl-info/parent
   /rpl-info/rank
   /rpl-info/link-metric

These resources allow to toggle led on board (if boards supports) and build
rpl mesh network topology from node rpl information.

Building And Running
********************

If border router is a Sparrow border router, follow below steps to build and
run Sparrow BR. Sparrow has it's own TLV mechanism to build topology. Zephyr
doesn't support it. So a patch provided in this folder to support for building
topology with CoAP based response.

Running Sparrow BR
==================

.. code-block:: console

   git clone https://github.com/sics-iot/sparrow.git
   cd sparrow
   git am 0001-Added-CoAP-support-for-Sparrow-Border-Router.patch
   cd products/sparrow-border-router
   sudo make connect-high PORT=/dev/ttyACM0

Wait until border-router up and running. For web based UI run below python
script. Unset if your pc is under proxy.

.. code-block:: console

   cd examples/sparrow
   ./wsdemoserver.py

Wait until you see "Connected" message on console. Unset proxy in browser
and open 127.0.0.1:8000.

Running RPL node
================

To build and run RPL node, follow the below steps to build and install
it on IEEE 802.15.4 radio supported board.

.. code-block:: console

    make pristine and make flash

Wait until RPL node joins with Border-Router and update the list in web UI.
