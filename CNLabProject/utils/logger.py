import datetime
from core.paths import LOG_PATH


def log(message):
    timestamp = datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    formatted = f'[{timestamp}] {message}'
    print(formatted)
    with LOG_PATH.open('a', encoding='utf-8') as handle:
        handle.write(formatted + '\n')
