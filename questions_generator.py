import json
import os
import random
import shutil
import time
import uuid
from pathlib import Path

from decouple import config
from selenium import webdriver
from selenium.webdriver.chrome.service import Service
from selenium.webdriver.common.by import By
from selenium.webdriver.common.keys import Keys
from selenium.webdriver.support import expected_conditions as EC
from selenium.webdriver.support.ui import WebDriverWait
from webdriver_manager.chrome import ChromeDriverManager

from questions import BASE_URL, question_generator
import pyperclip
import re
from typing import List


def should_run_chrome_headless():
    value = os.environ.get("CHROME_HEADLESS", "").lower()
    if value in {"1", "true", "yes", "on"}:
        return True
    if value in {"0", "false", "no", "off"}:
        return False
    return os.environ.get("CI", "").lower() == "true"


class GenerateQuestions:
    def __init__(self, teardown=False):

        s = Service(ChromeDriverManager().install())
        self.options = webdriver.ChromeOptions()
        for argument in (
            "--no-sandbox",
            "--disable-dev-shm-usage",
            "--disable-gpu",
            "--window-size=1920,1080",
        ):
            self.options.add_argument(argument)

        if should_run_chrome_headless():
            self.options.add_argument("--headless=new")

        # ensure window is visible and starts maximized
        self.options.add_argument('--start-maximized')
        self.teardown = teardown
        # keep chrome open after chromedriver exits
        self.options.add_experimental_option("detach", True)
        self.options.add_experimental_option(
            "excludeSwitches",
            ['enable-logging'])
        self.driver = webdriver.Chrome(
            options=self.options,
            service=s)
        self.driver.implicitly_wait(50)
        self.collections_url = []
        super(GenerateQuestions, self).__init__()

    def __enter__(self):
        self.driver.get(BASE_URL)
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        if self.teardown:
            self.driver.quit()

    def toggle_deep_research(self):
        wait = WebDriverWait(self.driver, 20)

        xpath = '//button[.//span[normalize-space(text())="Fast"]]'
        btn = wait.until(EC.element_to_be_clickable((By.XPATH, xpath)))
        btn.click()

        xpath_primary = "//div[@role='menuitem' and .//span[normalize-space(text())='Deep Research']]"
        menu_item = wait.until(EC.element_to_be_clickable((By.XPATH, xpath_primary)))
        menu_item.click()

    def ask_question(self, question_gotten):
        wait = WebDriverWait(self.driver, 1200)
        self.driver.get(BASE_URL)

        wait.until(
            EC.presence_of_element_located((By.CSS_SELECTOR, 'form'))
        )

        for _ in range(10):
            try:

                # # wait for the form containing the textarea
                form = wait.until(
                    EC.presence_of_element_located((By.CSS_SELECTOR, 'form'))
                )

                # find the textarea inside the form
                textarea = form.find_element(By.CSS_SELECTOR, 'textarea')
                self.toggle_deep_research()
                # type the question
                textarea.click()
                textarea.clear()
                formatted_question = question_generator(question_gotten)

                # Use JavaScript to set the textarea value directly. It's more reliable for large text.
                self.driver.execute_script("arguments[0].value = arguments[1];", textarea, formatted_question)
                # Dispatch an 'input' event to make sure the web application detects the change.
                self.driver.execute_script("arguments[0].dispatchEvent(new Event('input', { bubbles: true }));",
                                           textarea)
                textarea.send_keys(".. ")

                textarea.send_keys(Keys.ENTER)

                time.sleep(10)
                current_url = self.driver.current_url

                # add the current url to collections
                self.save_to_questions(question_gotten, current_url)
                break
            except Exception as a:
                print(f"There was an error")
                print(f"{self.driver.current_url}")
                time.sleep(10)
                continue

                # In your Deepwiki class where you save to questions.json

    def save_to_questions(self, question_gotten, url):
        """Save question and URL to questions.json"""
        collections_file = config("SCOPE_QUESTIONS_PATH")

        # Load existing data or start fresh
        try:
            if os.path.exists(collections_file):
                with open(collections_file, "r") as f:
                    content = f.read().strip()
                    data = json.loads(content) if content else []
            else:
                data = []
        except json.JSONDecodeError:
            print("Invalid questions.json, creating new file")
            data = []

        # Add new entry
        data.append({
            "question": question_gotten,
            "url": url,
            "questions_generated": False
        })

        # Save with proper formatting
        try:
            with open(collections_file, "w") as f:
                json.dump(data, f, indent=2, ensure_ascii=False)
        except Exception as e:
            print(f"Error saving to collections: {e}")


class GetQuestions:
    def __init__(self, teardown=False, show_browser=False):

        s = Service(ChromeDriverManager().install())
        self.options = webdriver.ChromeOptions()
        for argument in (
            "--no-sandbox",
            "--disable-dev-shm-usage",
            "--disable-gpu",
            "--window-size=1920,1080",
        ):
            self.options.add_argument(argument)

        if not show_browser:
            self.options.add_argument("--headless=new")

        # ensure window is visible and starts maximized
        self.options.add_argument('--start-maximized')
        self.teardown = teardown
        # keep chrome open after chromedriver exits
        self.options.add_experimental_option("detach", True)
        self.options.add_experimental_option(
            "excludeSwitches",
            ['enable-logging'])
        self.driver = webdriver.Chrome(
            options=self.options,
            service=s)
        self.driver.implicitly_wait(50)
        self.collections_url = []
        self.chunk_size = 25
        self.pending_questions = []
        super(GetQuestions, self).__init__()

    def _save_question_folder(self, questions, scanned_directory):
        folder_name = str(uuid.uuid4())
        folder_path = os.path.join(scanned_directory, folder_name)
        os.makedirs(folder_path, exist_ok=True)

        for question in questions:
            filename = f"question_{uuid.uuid4()}.md"
            filepath = os.path.join(folder_path, filename)

            with open(filepath, 'w', encoding='utf-8') as f:
                f.write(question)
                f.write("\n")

        print(f"Saved {len(questions)} questions to {folder_path}")

    def _save_complete_question_batches(self, scanned_directory):
        saved_folders = 0

        while len(self.pending_questions) >= self.chunk_size:
            chunk = self.pending_questions[:self.chunk_size]
            self.pending_questions = self.pending_questions[self.chunk_size:]
            self._save_question_folder(chunk, scanned_directory)
            saved_folders += 1

        return saved_folders

    def flush_remaining_questions(self):
        scanned_directory = os.environ.get('SCANNED_DIR', 'scanned')
        os.makedirs(scanned_directory, exist_ok=True)

        if not self.pending_questions:
            return

        self._save_question_folder(self.pending_questions, scanned_directory)
        self.pending_questions = []

    def get_questions(self, url):
        scanned_directory = os.environ.get('SCANNED_DIR', 'scanned')
        os.makedirs(scanned_directory, exist_ok=True)

        try:
            self.driver.get(url)

            wait = WebDriverWait(self.driver, 20)
            #  this would click the copy button
            copy_button_selector = (By.CSS_SELECTOR, '[aria-label="Copy"]')
            all_copy_buttons = wait.until(
                EC.presence_of_all_elements_located(copy_button_selector)
            )
            last_copy_button = all_copy_buttons[-1]
            wait.until(EC.element_to_be_clickable(last_copy_button)).click()

            xpath = "//div[@role='menuitem' and normalize-space(text())='Copy response']"
            el = wait.until(EC.element_to_be_clickable((By.XPATH, xpath)))
            el.click()

            clipboard_content = pyperclip.paste()

            all_questions = self.get_question_content(clipboard_content)

            try:
                total_questions = len(all_questions)
                self.pending_questions.extend(all_questions)
                saved_folders = self._save_complete_question_batches(scanned_directory)

                print(
                    f"\nExtracted {total_questions} questions, saved {saved_folders} full folders, "
                    f"{len(self.pending_questions)} questions waiting for next batch"
                )
            except Exception as a:
                print(a)

        except Exception as e:
            print(f"An error occurred: {str(e)}")

    def get_question_content(self, clip_board_content: str) -> List[str]:
        """
            Extracts security audit questions from the provided text using regex.
            """
        pattern = r'"(\[File:.*?)"'
        questions = re.findall(pattern, clip_board_content, flags=re.DOTALL)
        # Optional: Clean up whitespace (strip) for each question found
        return [q.strip() for q in questions]


def generate_file_path_for_scope():
    # Get the directory from environment variable, or use 'questions' as default
    scope_questions_directory = os.environ.get('SCOPE_QUESTIONS_DIR', 'scope_questions')
    scope_directory = os.environ.get("QUESTION_DIR", 'scope')
    scope_pending_directory = os.environ.get("SCOPE_PENDING_DIR", 'scope_pending')

    # Create the directories if they don't exist
    os.makedirs(scope_questions_directory, exist_ok=True)
    os.makedirs(scope_directory, exist_ok=True)
    os.makedirs(scope_pending_directory, exist_ok=True)

    scope_files = sorted(Path(scope_directory).glob('*.json'))

    if not scope_files:
        raise FileNotFoundError(f"No scope files found in {scope_directory}")

    # Get the first file
    source_file = random.choice(scope_files)
    file_name = source_file.name

    # Define destination path in pending directory
    destination_file = Path(scope_pending_directory) / file_name
    questions_file = f"{source_file.stem}.json"  # Keep the same filename but ensure .json extension

    try:
        # Move the file to pending directory
        source_file.rename(destination_file)
        print(f"Moved {file_name} to {scope_pending_directory}")
    except Exception as e:
        raise IOError(f"Failed to move {file_name} to {scope_pending_directory}: {e}")

    # Generate file path
    file_path = os.path.join(scope_questions_directory, questions_file)

    # Create or update .env file with the file path
    env_path = os.path.join(os.path.dirname(__file__), '.env')
    with open(env_path, 'w') as f:
        f.write(f"SCOPE_QUESTIONS_PATH={file_path}\n")

    os.environ['SCOPE_QUESTIONS_PATH'] = file_path
    print(os.environ.get('SCOPE_QUESTIONS_PATH'))

    return str(questions_file)


def generate_file_path_get_questions():
    question_directory = os.environ.get("QUESTIONS_DIR", "questions")
    scope_questions_directory = os.environ.get('SCOPE_QUESTIONS_DIR', 'scope_questions')
    scope_questions_pending_directory = os.environ.get("SCOPE_QUESTIONS_PENDING_DIR", 'scope_questions_pending')

    # Create the directories if they don't exist
    os.makedirs(question_directory, exist_ok=True)
    os.makedirs(scope_questions_directory, exist_ok=True)
    os.makedirs(scope_questions_pending_directory, exist_ok=True)

    # Get all JSON files in the questions directory
    questions_files = sorted(Path(scope_questions_directory).glob('*.json'))

    if not questions_files:
        raise FileNotFoundError("No questions files found")

    moved_files = []
    counter = 0

    # Move up to 20 files
    for file_path in questions_files:
        try:
            if counter >= 20:
                break

            # Create destination path
            dest_path = os.path.join(scope_questions_pending_directory, file_path.name)

            # Skip if file with same name already exists in destination
            if os.path.exists(dest_path):
                # Append a timestamp to make filename unique
                base_name = file_path.stem
                extension = file_path.suffix
                timestamp = int(time.time())
                dest_path = os.path.join(scope_questions_pending_directory, f"{base_name}_{timestamp}{extension}")

            # Move the file
            shutil.move(str(file_path), dest_path)
            moved_files.append(dest_path)
            counter += 1
            print(f"Moved {file_path} to {dest_path}")

        except Exception as e:
            print(f"Error moving {file_path}: {e}")
            continue

    if not moved_files:
        print("No files were moved")
        return None

    print(f"Successfully moved {len(moved_files)} files to {scope_questions_pending_directory}")
    return moved_files
