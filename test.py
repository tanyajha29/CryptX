import os
from selenium import webdriver
from selenium.webdriver.chrome.options import Options

options = Options()
options.add_argument("--headless")
options.add_argument("--no-sandbox")
options.add_argument("--disable-dev-shm-usage")

remote_url = os.getenv("SELENIUM_REMOTE_URL")

driver = webdriver.Remote(
    command_executor=remote_url,
    options=options
)

driver.get("http://13.48.42.165:5000")

print("Title:", driver.title)

driver.quit()
