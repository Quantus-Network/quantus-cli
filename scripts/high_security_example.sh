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
quantus reversible schedule-transfer-with-delay --from crystal_alice --to crystal_bob --amount 555 --delay-seconds 90

# Check balances of Alice and Charlie
quantus balance --address crystal_alice
quantus balance --address crystal_charlie

# Alice sends a reversible transfer to bob over 500000 coins of quantus over 1 hour delay
quantus reversible schedule-transfer-with-delay --from crystal_alice --to crystal_bob --amount 500000 --delay 3600

# Alice should be able to cancel the reversible transfer
# quantus reversible cancel --tx-id <tx-id> --from crystal_alice

# Charlie intercepts the transfer and sends it to himself
quantus reversible schedule-transfer-with-delay --from crystal_charlie --to crystal_charlie --amount 555 --delay 3600

# Check balances of Alice, Bob, and Charlie
quantus balance --address crystal_alice
quantus balance --address crystal_bob
quantus balance --address crystal_charlie

# Charlie pulls all money from Alice's account
# this is simply done by charlie making a transfer on behalf of alice which sends all money to charlie
# We need to use the proxy pallet for this
# because Charlie is a guardian for alice, charlie is also a recoverer through the recovery pallet. 
# so we can use the recovery pallet to send all money to charlie
quantus recovery recover-all --rescuer crystal_charlie --lost crystal_alice --dest crystal_charlie

# Check balances of Alice, Bob, and Charlie
quantus balance --address crystal_alice
quantus balance --address crystal_bob
quantus balance --address crystal_charlie