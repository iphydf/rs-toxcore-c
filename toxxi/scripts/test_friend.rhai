// Test script to add a friend and wait for them to come online.
let tox_id = "13117C65771C5A05409F532A7809D238E38E94312C870FE7970C5B65B1215E20CEF40A1D48B7";
let message = "Hello there!";

print("Step 0: Setting script timeout (1m)...");
timeout("60000");

print("Step 0.1: Setting identity...");
nick("Obi-Wan Kenobi");
status("I am a Rhai script");

print("Step 1: Adding friend " + tox_id);
friend("add " + tox_id + " " + message);

print("Step 2: Waiting for Tox network connection...");
wait_online();
print("Connected to network.");

print("Step 3: Waiting for friend (ID 0) to come online...");
// Assuming this is a fresh profile, the first added friend will be index 0.
wait_friend_online(0);

print("Step 4: Friend is online! Sending message...");
msg("0 Friend verified. This is an automated message.");

print("Step 5: Waiting for read receipt...");
wait_read_receipt(0);

print("Script completed successfully.");
quit();
