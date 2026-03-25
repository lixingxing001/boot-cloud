#FROM eclipse-temurin:8-jre
FROM eclipse-temurin:17-jdk

# 说明：
# - 使用统一容器目录结构，便于多服务脚手架复用
# - 构建产物约定为 target/boot-cloud-base.jar

ARG APP_NAME=boot-cloud-base

# 接收镜像信息构建参数（便于排障：容器内 /app-image-info.properties）
ARG IMAGE_NAME=unknown
ARG IMAGE_TAG=unknown
ARG BUILD_TIME=unknown

ENV BASE_PATH /home
ENV APP_PATH $BASE_PATH/apps/$APP_NAME
ENV LOG_PATH $BASE_PATH/logs/$APP_NAME
RUN mkdir -p $LOG_PATH $APP_PATH

# 将镜像信息写入文件，应用启动时可以读取并打印（便于定位“跑的是哪个镜像”）
RUN echo "image.name=${IMAGE_NAME}" > /app-image-info.properties && \
    echo "image.tag=${IMAGE_TAG}" >> /app-image-info.properties && \
    echo "build.time=${BUILD_TIME}" >> /app-image-info.properties

# JVM 默认参数（可通过 JVM_XMS/JVM_XMX/JAVA_OPTS/BOOT_OPTIONS 覆盖或追加）
ENV BUILDIN_JAVA_OPTS="\
        -XX:InitialRAMPercentage=75.0 \
        -XX:MaxRAMPercentage=75.0 \
        -XX:+UseG1GC \
        -Xss256k \
        -XX:MaxGCPauseMillis=150 \
        -XX:G1HeapRegionSize=4m \
        -XX:G1ReservePercent=15 \
        -XX:InitiatingHeapOccupancyPercent=35 \
        -XX:ConcGCThreads=4 \
        -XX:ParallelGCThreads=8 \
        -XX:+ParallelRefProcEnabled \
        -XX:+PerfDisableSharedMem \
        -XX:-OmitStackTraceInFastThrow \
        -XX:SoftRefLRUPolicyMSPerMB=0 \
        -XX:+AlwaysPreTouch \
        -XX:+UseStringDeduplication \
        -XX:MaxDirectMemorySize=256M \
        -Xlog:gc*:file=${LOG_PATH}/${APP_NAME}_gc.log:time,pid,tags:filecount=5,filesize=30M"

ENV JVM_XMS=256m
ENV JVM_XMX=512m

COPY ./target/$APP_NAME.jar $APP_PATH/app.jar

ENTRYPOINT [ "sh", "-c", "java -server -Xms$JVM_XMS -Xmx$JVM_XMX $BUILDIN_JAVA_OPTS $JAVA_OPTS -jar $APP_PATH/app.jar $BOOT_OPTIONS" ]

