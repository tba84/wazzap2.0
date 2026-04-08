# **CMPT 371 A3 Socket Programming `Secure Chat Application`**

**Course:** CMPT 371 - Data Communications & Networking  
**Instructor:** Mirza Zaeem Baig  
**Semester:** Spring 2026  

<span style="color: purple;">***RUBRIC NOTE: As per submission guidelines, only one group member should submit the GitHub repository link on Canvas.***</span>

## **Group Members**

| Name | Student ID | Email |
| :---- | :---- | :---- |
| Taha Ben Romdhane | 301624808 | tba83@sfu.ca |
| Danny Choi | 301557678 | partner_email@university.edu |

---

## **1. Project Overview & Description**

This project is a multithreaded client-server messaging application built in Python using the TCP Socket API and wrapped in a browser-based local web interface. It allows multiple users to create accounts, sign in, and exchange direct messages through a central server. The server manages active sessions, stores undelivered messages for offline users, and forwards them when the recipient reconnects.

The latest version of the project presents the system as a local web app called **Wazzap**, with:
- a landing page
- a dedicated **Server Dashboard**
- a dedicated **Client Chat UI**
- live conversation updates
- offline message delivery
- graceful disconnect and shutdown handling
- end-to-end encrypted message delivery using public-key cryptography

The application demonstrates practical networking concepts such as TCP communication, client/server session handling, multithreading, message framing, delivery tracking, and secure message exchange over sockets.

---

## **2. System Limitations & Edge Cases**

As required by the project specifications, we identified and handled the following limitations and edge cases within the scope of the application:

### **Abrupt Client Disconnection**
- <span style="color: green;">*Solution:*</span> If a client disconnects unexpectedly, the server catches socket-related exceptions, marks that client offline, and prevents the rest of the server from crashing.
- <span style="color: red;">*Limitation:*</span> If a client disconnects in the middle of an in-progress send/receive operation, a delivery acknowledgement may be delayed until the next state update.

### **Offline Message Delivery**
- <span style="color: green;">*Solution:*</span> Messages for offline users are stored in the server-side mailbox database and delivered once the user signs in again.
- <span style="color: red;">*Limitation:*</span> Messages are stored in memory during runtime only, so they are not persistent if the Python process is terminated.

### **Handling Multiple Clients Concurrently**
- <span style="color: green;">*Solution:*</span> The backend uses Python threads so it can accept new clients, monitor shutdown, deliver queued messages, and manage multiple browser-backed chat sessions independently.
- <span style="color: red;">*Limitation:*</span> This architecture is suitable for the assignment, but it is not intended to scale like a production-grade async or distributed chat platform.

### **TCP Stream Buffering**
- <span style="color: green;">*Solution:*</span> Since TCP is a byte stream and does not preserve message boundaries, the project uses application-layer line framing and buffered parsing to separate messages correctly.
- <span style="color: red;">*Limitation:*</span> If the framing convention is broken by a modified client, incoming messages may not parse correctly.

### **End-to-End Encryption**
- <span style="color: green;">*Solution:*</span> Each user generates or loads an RSA keypair locally, requests the recipient’s public key, encrypts plaintext before sending, and decrypts ciphertext only on the receiver side.
- <span style="color: red;">*Limitation:*</span> This academic version does not authenticate public keys using certificates or fingerprints, so it is not hardened against a malicious key-substitution server.

### **Browser UI Behavior**
- <span style="color: green;">*Solution:*</span> The project now uses a local browser UI instead of raw terminal prompts, making authentication, chat selection, sending, and monitoring much easier to demonstrate.
- <span style="color: red;">*Limitation:*</span> The interface still depends on the local Python backend and browser compatibility for correct rendering and interaction.

---

## **3. Video Demo**

<span style="color: purple;">***RUBRIC NOTE: Include a clickable video link here before submission.***</span>

Our short demonstration video covering:
- launching the local web app
- starting the socket backend
- user signup/signin
- creating chats
- sending and receiving messages
- offline delivery
- disconnect flow
- server dashboard monitoring
- graceful server shutdown

can be viewed here:

[**▶️ Watch Project Demo**](PASTE_YOUR_VIDEO_LINK_HERE)

---

## **4. Prerequisites (Fresh Environment)**

To run this project, you need:

- **Python 3.10+**
- the **cryptography** package installed
- a modern web browser

### **Install dependency**
```bash
pip install cryptography
```

---

## **5. Project Files**

Example project layout:

```bash
.
├── app.py
├── backend.py
├── README.md
├── static/
│   ├── index.html
│   ├── client.html
│   ├── server.html
│   └── style.css
└── client_keys/
```

### **Main files**
- `app.py`  
  Starts the local web server, serves the browser UI, exposes the API routes, and manages browser client sessions.
- `backend.py`  
  Handles the socket-based backend logic including authentication, delivery, offline storage, encryption support, and graceful cleanup.

### **Static assets**
- `static/index.html`  
  The landing page for the project.
- `static/client.html`  
  The browser chat interface for users.
- `static/server.html`  
  The browser dashboard for backend control and monitoring.
- `static/style.css`  
  Shared styling for the UI.

### **Generated folder**
- `client_keys/`  
  Created automatically to store RSA private/public key files for users.

---

## **6. Step-by-Step Run Guide**

<span style="color: purple;">***RUBRIC NOTE: The grader should be able to follow these steps exactly.***</span>

### **Step 1: Start the Application**

Open a terminal in the project folder and run:

```bash
python app.py
```

This starts the local web server for the browser-based interface.

By default, the web UI is served at:

```text
http://127.0.0.1:8000/
```

---

### **Step 2: Open the Web App**

Open the following page in your browser:

```text
http://127.0.0.1:8000/
```

This landing page provides two navigation options:
- **Open Client**
- **Open Server Dashboard**

You may also open the pages directly:

- **Landing page:** `http://127.0.0.1:8000/`
- **Client page:** `http://127.0.0.1:8000/client`
- **Server dashboard:** `http://127.0.0.1:8000/server`

---

### **Step 3: Start the Socket Backend from the Server Dashboard**

On the **Server Dashboard** page:

1. Optionally enter a port number in **Socket server port**
   - entering `0` lets the system choose an available port automatically
2. Click **Start server**
3. Wait until the dashboard shows that the backend is running
4. Note the **Backend host** and **Backend port** values displayed on the dashboard

The dashboard also shows:
- whether the backend is running
- the backend host and port
- the current queued message count
- known users and whether they are online
- mailbox statistics
- live backend logs

These values are needed by browser clients when they authenticate.

---

### **Step 4: Open a Client Page and Authenticate**

Go to the **Client** page:

```text
http://127.0.0.1:8000/client
```

On the authentication screen:

1. Enter the **server host**  
   Usually this is `127.0.0.1`
2. Enter the **server port** shown on the server dashboard
3. Choose either:
   - **Sign in** if the user already exists
   - **Sign up** if creating a new account
4. Enter the username and password
5. Click the submit button

After successful authentication, the chat interface opens.

---

### **Step 5: Use the Chat Interface**

Once logged in, the browser client shows a chat layout with:

- a user label in the sidebar
- a **Search chats** field
- a conversation list with the most recent discussion shown first
- a **+** button to start a new discussion
- a message feed for the selected conversation
- a composer box with a **Send** button
- a **Disconnect** button in the sidebar

If no chat is selected yet, the main panel shows an empty-state message prompting the user to choose or create a conversation.

---

### **Step 6: Start a New Conversation**

To begin chatting with another user:

1. Click the **+** button
2. In the modal window, type the **exact username** of the recipient
3. Click **Open chat**

The chat opens in the main panel immediately.  
If the username does **not** exist, the send attempt will fail and the UI will show an error when you try to send the first message.

---

### **Step 7: Send Messages**

Inside an open conversation:

1. Type the message in the input field at the bottom
2. Click **Send**

The system will display the message in the conversation feed and update delivery state.

- If the recipient is online, the message is delivered immediately
- If the recipient is offline, the message is stored and delivered when they reconnect

Outgoing messages may appear with delivery status such as:
- **Pending**
- **Delivered**

---

### **Step 8: View Existing Conversations**

The left sidebar displays conversation history for the logged-in user.

For each conversation, the UI may show:
- the contact’s username
- whether the contact is currently online
- a preview of the latest message

You can click any conversation in the list to reopen it.

You can also use the **Search chats** field to filter the conversation list.

---

### **Step 9: Disconnect a Client**

To end the current browser client session:

1. Click the **Disconnect** button in the sidebar

This returns the user to the authentication screen and disconnects that browser session from the socket backend.

**Note:** Closing or refreshing the browser tab also attempts to disconnect that session cleanly.

---

### **Step 10: Shut Down the Server**

To stop the socket backend:

1. Return to the **Server Dashboard**
2. Click **Shutdown**

After shutdown, active browser clients will no longer be able to send or receive messages until the backend is started again.

---

## **7. Typical Demonstration Flow**

A simple demonstration of the program can follow this order:

1. Run `python app.py`
2. Open `http://127.0.0.1:8000/`
3. Open the **Server Dashboard**
4. Start the socket backend
5. Open the **Client** page in one browser tab and sign up as **User A**
6. Open the **Client** page in another browser tab and sign up or sign in as **User B**
7. Create a new chat using the **+** button
8. Exchange messages between both users
9. Disconnect one user and send a message while they are offline
10. Sign that user back in and confirm the queued message is shown
11. Return to the server dashboard and shut the backend down

---

## **8. Technical Design Summary**

### **Server Responsibilities**
- accept incoming TCP connections
- manage signup/signin
- track online users
- queue undelivered messages
- forward outgoing messages
- handle shutdown and disconnect cleanup
- expose browser-facing API endpoints
- provide a web dashboard for monitoring backend activity

### **Client Responsibilities**
- connect to the backend through the browser UI
- authenticate with username/password
- display conversation history and new messages
- open new chats
- send encrypted outgoing messages
- decrypt incoming ciphertext
- disconnect cleanly from the backend

### **Protocol Notes**
This project uses a custom application-layer protocol over TCP for backend communication, while exposing a browser-based UI through a local HTTP server. The system includes:
- authentication messages
- public-key exchange requests/responses
- encrypted message forwarding
- delivery acknowledgements
- buffered line-based message framing
- browser interaction through JSON API endpoints

Because TCP is stream-oriented, the application must define its own boundaries between messages.

---

## **9. How to Test the Main Cases**

### **Case 1: Normal Online Messaging**
1. Start the application
2. Start the socket backend from the server dashboard
3. Sign in two users from two browser tabs
4. Send a message from one to the other
5. Confirm immediate receipt

### **Case 2: Offline Delivery**
1. Disconnect one user
2. Send messages to that user
3. Sign that user back in
4. Confirm queued delivery on reconnect

### **Case 3: Abrupt Disconnect**
1. Start messaging between two users
2. Force-close one browser tab or otherwise interrupt one session
3. Confirm the backend continues running

### **Case 4: Clean Client Disconnect**
1. Click **Disconnect**
2. Confirm the user returns to the authentication screen without crashing the backend

### **Case 5: Server Shutdown**
1. Click **Shutdown** on the server dashboard
2. Confirm the backend stops and clients lose the connection cleanly

---

## **10. Academic Integrity & References**

### **Code Origin**
- The core socket-based client/server messaging logic was implemented for this course project.
- The browser-based UI was added to improve usability and demonstrate the system more clearly.
- The README structure was adapted from our earlier assignment README format and updated to reflect the final UI.

### **GenAI Usage**
- ChatGPT was used to help debug threading, socket shutdown handling, offline message delivery, encryption flow, UI-aligned README drafting, and integration refinements.
- Any generated suggestions were reviewed, tested, and integrated manually by the group.

### **References**
- Python Software Foundation. *Socket Programming HOWTO*. https://docs.python.org/3/howto/sockets.html
- Python Software Foundation. *socket — Low-level networking interface*. https://docs.python.org/3/library/socket.html
- Python Software Foundation. *threading — Thread-based parallelism*. https://docs.python.org/3/library/threading.html
- `cryptography` documentation. *RSA*. https://cryptography.io/en/latest/hazmat/primitives/asymmetric/rsa/
- GitHub Docs. *Basic writing and formatting syntax*. https://docs.github.com/github/writing-on-github/getting-started-with-writing-and-formatting-on-github/basic-writing-and-formatting-syntax


---

## **11. Readability Notes**

This version of the source code includes explanatory comments in the main files so that a
new reader can follow:

- the role of each Python module
- how shared state is protected with locks
- how the socket protocol is structured
- how RSA public-key encryption is used
- how the browser pages communicate with `app.py`
- how the chat and dashboard pages render and refresh their state
