FROM ubuntu:latest

ENV LANG C.UTF-8
ENV LC_ALL C.UTF-8

ENV GRADLE_VERSION 7.6
ENV GHIDRA_INSTALL_DIR /ghidra
ENV GRADLE_USER_HOME /home/gradle

ARG UID=1000
ARG GID=1000
ARG USER=gradle
ARG GRADLE_CHECKSUM=7ba68c54029790ab444b39d7e293d3236b2632631fb5f2e012bb28b4ff669e4b

RUN apt-get -yq update \
    && apt-get -yq install openjdk-17-jre openjdk-17-jdk wget unzip \
    && groupadd --gid ${GID} gradle \
    && useradd -m ${USER} --uid=${UID} --gid ${GID}

COPY ghidrachatgpt /build
COPY data/entry /entry

RUN chmod +x /entry \
    && chown -R ${USER}:${USER} /build

RUN wget -q -O gradle.zip "https://downloads.gradle-dn.com/distributions/gradle-${GRADLE_VERSION}-bin.zip" \
    && echo "${GRADLE_CHECKSUM} gradle.zip" | sha256sum --check - \
    && unzip gradle.zip && rm gradle.zip

USER ${USER}
WORKDIR /build

CMD ["/entry"]