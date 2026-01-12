#!/bin/bash

# High Security Example Script
# This script demonstrates the high security features of the Quantus blockchain.
# It sets up a guardian for an account and demonstrates the reversible transfer functionality.
# It also demonstrates the recovery pallet functionality.

# set this to your binary
alias quantus="./target/release/quantus --node-url ws://127.0.0.1:9944"

# Alice sets charlie as her guardian with a 1 hour delay 
quantus high-security set --from crystal_alice --interceptor crystal_charlie --delay-seconds 3600

# Check the status of the high security
quantus high-security status --account crystal_alice

# fail case 1 Alice sets bob as her interceptor - this should fail because alice already has a guardian
quantus high-security set --from crystal_alice --interceptor crystal_bob --delay-seconds 3600

# fail case 2 could also try to send a normal tx - should fail
quantus send --from crystal_alice --to crystal_bob --amount 9999

# fail case 3 also send a reversible with a different delay more or less - should fail
quantus reversible schedule-transfer-with-delay --from crystal_alice --to crystal_bob --amount 5556 --delay 90

# Check balances of Alice and Charlie
quantus balance --address crystal_alice
quantus balance --address crystal_charlie

# Alice sends a reversible transfer to bob over 500000 coins of quantus over 1 hour delay
quantus reversible schedule-transfer --from crystal_alice --to crystal_bob --amount 500000

quantus reversible list-pending --from crystal_alice

# Interceptor account charlie reverses transaction 
quantus reversible cancel --tx-id 0xb8ee1f940e13fbc171481d1b06967760bf1d39f06dbcdb595c02c420aec6a45e --from crystal_charlie

# Check balances of Alice, Bob, and Charlie
quantus balance --address crystal_alice
quantus balance --address crystal_bob
quantus balance --address crystal_charlie

# activate the recovery first vouch then claim.
ququantus recovery initiate --rescuer crystal_charlie --lost crystal_alice
quantus recovery active --rescuer crystal_charlie --lost crystal_alice
quantus recovery vouch --rescuer crystal_charlie --lost crystal_alice --friend crystal_charlie
quantus recovery claim --rescuer crystal_charlie --lost crystal_alice
quantus recovery proxy-of --rescuer crystal_charlie

# Charlie pulls all money from Alice's account
quantus recovery recover-all --rescuer crystal_charlie --lost crystal_alice --dest crystal_charlie

# Check balances of Alice, Bob, and Charlie
quantus balance --address crystal_alice
quantus balance --address crystal_bob
quantus balance --address crystal_charlie