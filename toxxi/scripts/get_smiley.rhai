// Add VaultBot as friend
print("Adding friend...");
friend("add 7e9ddad28167bc075c991979f1e0e48e44f52fe35cfaec94c9045d387f01093bfa8027502d0f script-bot");

// Wait for network connection
print("Waiting to be online...");
wait_online();

// Wait for friend 0 (assuming fresh profile) to be online
print("Waiting for friend to be online...");
wait_friend_online(0);

// Request file list
print("Requesting file list...");
msg("0 list");
sleep(2000);

// Request the smiley file
print("Requesting file...");
msg("0 get laugh_closed_eyes.png");

// Set a 10 second timeout for the whole operation
timeout("10000");

// Wait for file transfer request from bot
print("Waiting for file transfer...");
let file_id = wait_file_recv(0);

// Accept the file
print("Accepting file " + file_id + "...");
file("accept 0 " + file_id);


// Wait for confirmation message from bot that sending finished
print("Waiting for transfer to finish...");
wait_friend_msg(0, "Finished sending file: laugh_closed_eyes.png");

// Exit
print("Quitting...");
quit();
