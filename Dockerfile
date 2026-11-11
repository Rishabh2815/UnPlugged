FROM ubuntu:24.04 AS build
RUN apt-get update && apt-get install -y --no-install-recommends g++ cmake make libboost-system-dev nlohmann-json3-dev libssl-dev && rm -rf /var/lib/apt/lists/*
WORKDIR /app
COPY CMakeLists.txt ./
COPY src ./src
RUN cmake -S . -B build -DCMAKE_BUILD_TYPE=Release && cmake --build build -j2

FROM ubuntu:24.04
RUN apt-get update && apt-get install -y --no-install-recommends libboost-system1.83.0 libssl3 ca-certificates && rm -rf /var/lib/apt/lists/* && useradd --system --uid 10001 app
WORKDIR /app
COPY --from=build /app/build/upi-mesh /app/upi-mesh
COPY public /app/public
USER 10001
ENV PORT=8080
EXPOSE 8080
CMD ["/app/upi-mesh"]
