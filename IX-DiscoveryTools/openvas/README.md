<!---Copyright 2021, Battelle Energy Alliance, LLC-->
1. Install docker (https://docs.docker.com/engine/install/ubuntu/)
2. Build the container will take quite a bit of time. I suggest this is done overnight. `./build.sh`
3. Run the container. `./run.sh`
4. Give the container a minute to startup.
5. Try to run the test script. `python3 test.py` (inside poetry shell)