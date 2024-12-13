"""
A mitmproxy addon that injects a floating chatbot into web pages.
The chatbot appears in the bottom right corner and echoes back messages.

Usage:
    mitmproxy -s chatbot_addon.py
"""
from mitmproxy import ctx
from mitmproxy import http
import json
from bs4 import BeautifulSoup
import requests
import sys

UPDATED_CHATBOT = """
  <div
    id="floating-chatbot"
    style="
      position: fixed;
      bottom: 20px;
      right: 20px;
      width: 300px;
      height: 400px;
      background: white;
      border-radius: 10px;
      box-shadow: 0 2px 10px rgba(0, 0, 0, 0.2);
      display: flex;
      flex-direction: column;
      z-index: 10000;
      font-family: Arial, sans-serif;
      display: none;
    "
  >
    <div
      id="chatbot-header"
      style="
        padding: 10px;
        background: #007bff;
        color: white;
        border-radius: 10px 10px 0 0;
        cursor: pointer;
        display: flex;
        justify-content: space-between;
        align-items: center;
      "
    >
      <span>Chat with us</span>
      <button
        id="chatbot-close"
        style="
          background: none;
          border: none;
          color: white;
          cursor: pointer;
          font-size: 18px;
        "
      >
        ×
      </button>
    </div>
    <div
      id="chatbot-messages"
      style="
        flex-grow: 1;
        overflow-y: auto;
        padding: 10px;
        display: flex;
        flex-direction: column;
        gap: 10px;
      "
    ></div>
    <div
      id="chatbot-input"
      style="
        padding: 10px;
        border-top: 1px solid #eee;
        display: flex;
        gap: 10px;
      "
    >
      <input
        type="text"
        id="chatbot-text"
        placeholder="Type a message..."
        style="
          flex-grow: 1;
          padding: 8px;
          border: 1px solid #ddd;
          border-radius: 5px;
          outline: none;
        "
      />
      <button
        id="chatbot-send"
        style="
          background: #007bff;
          color: white;
          border: none;
          padding: 8px 15px;
          border-radius: 5px;
          cursor: pointer;
        "
      >
        Send
      </button>
    </div>
  </div>

  <!-- Floating button to open chat -->
  <div
    id="chatbot-trigger"
    style="
      position: fixed;
      bottom: 20px;
      right: 20px;
      width: 60px;
      height: 60px;
      background: #007bff;
      border-radius: 50%;
      display: flex;
      align-items: center;
      justify-content: center;
      cursor: pointer;
      box-shadow: 0 2px 10px rgba(0, 0, 0, 0.2);
      z-index: 10000;
    "
  >
    <svg
      width="24"
      height="24"
      viewBox="0 0 24 24"
      fill="none"
      stroke="white"
      stroke-width="2"
      stroke-linecap="round"
      stroke-linejoin="round"
    >
      <path
        d="M21 15a2 2 0 0 1-2 2H7l-4 4V5a2 2 0 0 1 2-2h14a2 2 0 0 1 2 2z"
      ></path>
    </svg>
  </div>

  <script>
    (function () {
      // Get DOM elements
      const chatbot = document.getElementById("floating-chatbot");
      const trigger = document.getElementById("chatbot-trigger");
      const closeBtn = document.getElementById("chatbot-close");
      const messagesContainer = document.getElementById("chatbot-messages");
      const input = document.getElementById("chatbot-text");
      const sendBtn = document.getElementById("chatbot-send");

      // Toggle chat visibility
      function toggleChat() {
        if (chatbot.style.display === "none") {
          chatbot.style.display = "flex";
          trigger.style.display = "none";
        } else {
          chatbot.style.display = "none";
          trigger.style.display = "flex";
        }
      }

      // Add message to chat
      async function addMessage(text, isUser = false) {
        const message = document.createElement("div");
        message.style.cssText = `
            padding: 8px 12px;
            border-radius: 10px;
            max-width: 80%;
            word-wrap: break-word;
            align-self: ${isUser ? "flex-end" : "flex-start"};
            background: ${isUser ? "#007bff" : "#f0f0f0"};
            color: ${isUser ? "white" : "black"};
        `;
        message.textContent = text;
        messagesContainer.appendChild(message);
        messagesContainer.scrollTop = messagesContainer.scrollHeight;
      }

      // Send message
      async function sendMessage() {
        const text = input.value.trim();
        if (!text) return;

        // Add user message
        addMessage(text, true);
        post_url = "http://127.0.0.1:8080/llm_endpoint";
        post_options = {
          method: "POST",
          headers: {
            "Content-Type": "application/json",
          },
          body: JSON.stringify({
            user_query: text,
          }),
        };
            
        console.time("Time:");
        fetch(post_url, post_options)
          .then(async (response) => {
            if (!response.ok) {
              console.log(response.status);
              console.log(await response.text());
              throw new Error("Something went wrong querying the LLM");
            }

            return await response.json();
          })
          .then(async (data) => {
            console.log(data);
            const json = await JSON.parse(data.llm_response);
            console.timeEnd("Time:");
            console.log(json.result);
            await addMessage(json.result);
            input.value = "";
          })
          .catch((err) => {
            console.log(err);
            input.value = "";
          });
      }

      // Event listeners
      trigger.addEventListener("click", toggleChat);
      closeBtn.addEventListener("click", toggleChat);
      sendBtn.addEventListener("click", sendMessage);
      input.addEventListener("keypress", (e) => {
        if (e.key === "Enter") sendMessage();
      });

      // Prevent dragging from propagating to parent page
      chatbot.addEventListener("mousedown", function (e) {
        e.stopPropagation();
      });
    })();
  </script>
"""

CHATBOT_HTML = """
<div id="floating-chatbot" style="
    position: fixed;
    bottom: 20px;
    right: 20px;
    width: 300px;
    height: 400px;
    background: white;
    border-radius: 10px;
    box-shadow: 0 2px 10px rgba(0,0,0,0.2);
    display: flex;
    flex-direction: column;
    z-index: 10000;
    font-family: Arial, sans-serif;
    display: none;
">
    <div id="chatbot-header" style="
        padding: 10px;
        background: #007bff;
        color: white;
        border-radius: 10px 10px 0 0;
        cursor: pointer;
        display: flex;
        justify-content: space-between;
        align-items: center;
    ">
        <span>Chat with us</span>
        <button id="chatbot-close" style="
            background: none;
            border: none;
            color: white;
            cursor: pointer;
            font-size: 18px;
        ">×</button>
    </div>
    <div id="chatbot-messages" style="
        flex-grow: 1;
        overflow-y: auto;
        padding: 10px;
        display: flex;
        flex-direction: column;
        gap: 10px;
    ">
    </div>
    <div id="chatbot-input" style="
        padding: 10px;
        border-top: 1px solid #eee;
        display: flex;
        gap: 10px;
    ">
        <input type="text" id="chatbot-text" placeholder="Type a message..." style="
            flex-grow: 1;
            padding: 8px;
            border: 1px solid #ddd;
            border-radius: 5px;
            outline: none;
        ">
        <button id="chatbot-send" style="
            background: #007bff;
            color: white;
            border: none;
            padding: 8px 15px;
            border-radius: 5px;
            cursor: pointer;
        ">Send</button>
    </div>
</div>

<!-- Floating button to open chat -->
<div id="chatbot-trigger" style="
    position: fixed;
    bottom: 20px;
    right: 20px;
    width: 60px;
    height: 60px;
    background: #007bff;
    border-radius: 50%;
    display: flex;
    align-items: center;
    justify-content: center;
    cursor: pointer;
    box-shadow: 0 2px 10px rgba(0,0,0,0.2);
    z-index: 10000;
">
    <svg width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="white" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
        <path d="M21 15a2 2 0 0 1-2 2H7l-4 4V5a2 2 0 0 1 2-2h14a2 2 0 0 1 2 2z"></path>
    </svg>
</div>

<script>
(function() {
    // Get DOM elements
    const chatbot = document.getElementById('floating-chatbot');
    const trigger = document.getElementById('chatbot-trigger');
    const closeBtn = document.getElementById('chatbot-close');
    const messagesContainer = document.getElementById('chatbot-messages');
    const input = document.getElementById('chatbot-text');
    const sendBtn = document.getElementById('chatbot-send');

    // Toggle chat visibility
    function toggleChat() {
        if (chatbot.style.display === 'none') {
            chatbot.style.display = 'flex';
            trigger.style.display = 'none';
        } else {
            chatbot.style.display = 'none';
            trigger.style.display = 'flex';
        }
    }

    // Add message to chat
    function addMessage(text, isUser = false) {
        const message = document.createElement('div');
        message.style.cssText = `
            padding: 8px 12px;
            border-radius: 10px;
            max-width: 80%;
            word-wrap: break-word;
            align-self: ${isUser ? 'flex-end' : 'flex-start'};
            background: ${isUser ? '#007bff' : '#f0f0f0'};
            color: ${isUser ? 'white' : 'black'};
        `;
        message.textContent = text;
        messagesContainer.appendChild(message);
        messagesContainer.scrollTop = messagesContainer.scrollHeight;
    }

    // Send message
    function sendMessage() {
        const text = input.value.trim();
        if (!text) return;

        // Add user message
        addMessage(text, true);

        // Echo back the message (you can modify this to integrate with a real chat service)
        setTimeout(() => {
            addMessage(`You said: ${text}`);
        }, 500);

        input.value = '';
    }

    // Event listeners
    trigger.addEventListener('click', toggleChat);
    closeBtn.addEventListener('click', toggleChat);
    sendBtn.addEventListener('click', sendMessage);
    input.addEventListener('keypress', (e) => {
        if (e.key === 'Enter') sendMessage();
    });

    // Prevent dragging from propagating to parent page
    chatbot.addEventListener('mousedown', function(e) {
        e.stopPropagation();
    });
})();
</script>
"""

"""
    The following dictionary contains the headers in chunks
        key:   header (from table of contents)
        value: content under the header
"""
content_chunks = {}
lastk_counter = 0
html_text = ""


class ChatbotAddon:
    def request(self, flow: http.HTTPFlow) -> None: 
        # set the preflight options that trigger when 
        # "Content-Type: application/json" is in a header
        if flow.request.method == "OPTIONS":
            flow.response = http.Response.make(
                200,  
                b"",  
                {
                    "Access-Control-Allow-Origin": "*",
                    "Access-Control-Allow-Methods": "GET, POST, OPTIONS",
                    "Access-Control-Allow-Headers": "Content-Type, Authorization",
                },
            )
        if flow.request.path == "/llm_endpoint" and flow.request.method == "POST":
            
            if not html_text: 
                flow.response = http.Response.make(
                    500,
                    json.dumps({ "msg": "The website was not loaded in" }),
                    { "Content-Type": "application/json" }
                )

            try:
                data = json.loads(flow.request.content)
                user_query = data.get("user_query", "")

                url = "https://a061igc186.execute-api.us-east-1.amazonaws.com/dev"
                x_api_key = "comp112Z5q0ssTVs1ejT9Y2RQXixxyWQLm7eckWUcSRIWAO"

                headers = {
                    'x-api-key': x_api_key
                }

                request = {
                    'model': '4o-mini',
                    'system': f"Answer the following query, the content is found after the query with delimiter: \r\n\r\n",
                    'query': f"{user_query}\r\n\r\n{html_text}",
                    'temperature': 0.0,
                    'lastk': 1,
                    'session_id': "GenericSession",
                }
              
                try:
                    response = requests.post(url, headers=headers, json=request)

                    if response.status_code == 200:
                        flow.response = http.Response.make(
                            200,
                            json.dumps({ "llm_response": response.text }),
                            { "Content-Type": "application/json" }
                        )

                    else:
                        flow.response = http.Response.make(
                            response.status_code,
                            json.dumps({ "llm_response": "Error" }),
                            { "Content-Type": "application/json" }
                        )

                except requests.exceptions.RequestException as e:
                    flow.response = http.Response.make(
                        500,
                        json.dumps({"error": f"Something went wrong making LLM request: {str(e)}"}),
                        {"Content-Type": "application/json"}
                    )

            except Exception as e:
                flow.response = http.Response.make(
                    500,
                    json.dumps({"error": str(e)}),
                    {"Content-Type": "application/json"}
                )

    def response(self, flow: http.HTTPFlow) -> None:
        # have to set the CORS options to allow post requests to the mitmproxy 
        flow.response.headers["Access-Control-Allow-Origin"] = "*"
        flow.response.headers["Access-Control-Allow-Methods"] = "GET, POST, OPTIONS"
        flow.response.headers["Access-Control-Allow-Headers"] = "Content-Type, Authorization"
        # Only inject into HTML responses
        if not flow.response.headers.get("content-type", "").startswith("text/html"):
            return
        
        # Don't inject if there's no response body
        if not flow.response.content:
            return
            
        html = flow.response.text
        html_parser = BeautifulSoup(html, 'html.parser')
        
        # parse through the header of contents for the relevant chunked sections
        table_contents = html_parser.find_all(class_="vector-toc-link"); 
        headers = [item["href"].replace("#", "") for item in table_contents]
 
        # splits the contents of the html page into a list of individual words 
        # assumes that the words are separated by spaces
        html_text = " ".join(list(filter(bool, html_parser.get_text().replace("\n", " ").split(" "))))

        ctx.log.info(html_text)

        # Inject the chatbot HTML before the closing body tag
        if "</body>" in html:
            flow.response.text = html.replace("</body>", f"{UPDATED_CHATBOT}</body>")

addons = [ChatbotAddon()]
