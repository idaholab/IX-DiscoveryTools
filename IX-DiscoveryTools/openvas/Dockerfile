#Copyright 2021, Battelle Energy Alliance, LLC
FROM securecompliance/gvm:21.4.0-v5
COPY init.sh init.sh
RUN ./init.sh
RUN /sync-all.sh
RUN sed -i '/\/sync-all.sh/d' start.sh
CMD '/start.sh'
