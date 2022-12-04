FROM

ENV GOPROXY=https://goproxy.cn,direct

COPY . /app
WORKDIR /app

RUN make build

FROM

LABEL author=""

RUN mkdir -p /app/natbee/bin && mkdir -p /app/natbee/conf

COPY --from=builder /app/bin/nbd /app/natbee/bin/
COPY --from=builder /app/bin/nb /app/natbee/bin/
COPY --from=builder /app/bin/nat_bpfel.o /app/natbee/bin/
COPY --from=builder /app/bin/fnat_bpfel.o /app/natbee/bin/
COPY ./docker/nbd.yaml /app/natbee/conf/

RUN setcap cap_net_raw+ep /app/bin/nbd

ENV PATH ${PATH}:/app/natbee/bin

CMD fmd -c /app/natbee/conf/nbd.yaml