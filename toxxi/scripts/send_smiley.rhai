// Add VaultBot as friend
print("Adding friend...");
friend("add 7e9ddad28167bc075c991979f1e0e48e44f52fe35cfaec94c9045d387f01093bfa8027502d0f script-bot");

// Wait for network connection
print("Waiting to be online...");
wait_online();

// Wait for friend 0 (assuming fresh profile) to be online
print("Waiting for friend to be online...");
wait_friend_online(0);

// Send the smiley file
print("Sending file...");
file("send 0 /src/workspace/qtox/smileys/Classic/laugh_closed_eyes.png");

// Wait for transfer to progress
print("Waiting 10 seconds for transfer...");
sleep(10000);

// Exit
print("Quitting...");
quit();
