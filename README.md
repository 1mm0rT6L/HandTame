# HandTame
OK, let me explain.
This code has two classes named Passive & Active Recon, as u can see.
The options have been commented in the source code.
You must complete the bellow and save it as ```.env```
```
GOOGLE_API_KEY=AIzaSyD_YourGoogleKeyHere123456
URLSCAN_API_KEY=12345678-1234-1234-1234-123456789abc
VT_API_KEY=your_virustotal_api_key_here
OTX_API_KEY=your_otx_api_key_here
BUILTWITH_API_KEY=your_builtwith_api_key
WHOISJSON_API_KEY=your_whoisjson_api_key
DISCORD_WEBHOOK=https://discord.com/api/webhooks/your_webhook_id/your_webhook_token
TELEGRAM_BOT_TOKEN=1234567890:ABCdefGHIjklMNOpqrsTUVwxyz
TELEGRAM_CHAT_ID=-123456789
```
At least,
```
git clone https://github.com/1mm0rT6L/HandTame.git && cd HandTame
python -m venv venv && source venv/bin/activate
pip install colorama dnspython googlesearch-python python-dotenv requests python-nmap
python HandTame.py
```
