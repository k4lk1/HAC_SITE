from celery.decorators import task
from celery.utils.log import get_task_logger

import subprocess

logger = get_task_logger(__name__)

@task(name="scan")
def scan(url):
    print("a")
    subprocess.call(['bash','script.sh', url ])
    return redirect('/reviews/')
