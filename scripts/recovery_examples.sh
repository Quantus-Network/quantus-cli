#!/bin/bash

# Recovery pallet is pretty intricate, this script contains most all the functions for high security
# and recovery. 

# Set up dev accounts before using this script
# quantus developer create-test-wallets

echo "# Complete High Security + Recovery Flow Commands

## 1. Setup High Security (Alice with Bob as Interceptor)
quantus high-security set --from crystal_alice --interceptor crystal_bob --delay-seconds 3600

## 2. Check High Security Status
quantus high-security status --account crystal_alice

## 3. Check Alice's Recovery Configuration
quantus recovery config --account crystal_alice

## 4. Bob Initiates Recovery for Alice
quantus recovery initiate --rescuer crystal_bob --lost crystal_alice

## 5. Bob Vouches for His Own Recovery Attempt
quantus recovery vouch --friend crystal_bob --lost crystal_alice --rescuer crystal_bob

## 6. Bob Claims Recovery (Proxy Setup)
quantus recovery claim --rescuer crystal_bob --lost crystal_alice

## 7. Verify Bob's Proxy Status
quantus recovery proxy-of --rescuer crystal_bob

## 8. Send Funds to Alice for Testing
quantus send --from crystal_bob --to crystal_alice --amount 100

## 9. Recover Specific Amount (10 QUAN)
quantus recovery recover-amount --rescuer crystal_bob --lost crystal_alice --dest crystal_charlie --amount-quan 10

## 10. Recover All Funds
quantus recovery recover-all --rescuer crystal_bob --lost crystal_alice --dest crystal_charlie

## 11. Check Balances Throughout Process
quantus balance --address crystal_alice
quantus balance --address crystal_bob
quantus balance --address crystal_charlie

## 12. Query Recovery Status
quantus recovery active --lost crystal_alice --rescuer crystal_bob
quantus recovery proxy-of --rescuer crystal_bob"