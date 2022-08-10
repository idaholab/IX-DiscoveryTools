#Copyright 2021, Battelle Energy Alliance, LLC
docker start gvm_autodiscover || docker run --detach --publish 8080:9392 --publish 9390:9390 --publish 5432:5432 -e "DB_PASSWORD=autopass" -e "AUTO_SYNC=false" -e "PASSWORD=admin" --name "gvm_autodiscover" gvm_autodiscover:latest
