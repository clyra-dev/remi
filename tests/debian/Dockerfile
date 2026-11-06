ARG DEBIAN_VERSION=bookworm
FROM debian:${DEBIAN_VERSION}
ENV DEBIAN_FRONTEND=noninteractive
RUN ["apt-get", "update"]
RUN ["apt-get", "install", "-y", "systemd", "systemd-sysv", "openssh-server", "dbus", "gnupg", "ca-certificates", "procps"]
RUN ["sh", "-c", "if test -f /usr/sbin/policy-rc.d; then mv /usr/sbin/policy-rc.d /usr/sbin/policy-rc.d.image; fi"]
STOPSIGNAL SIGRTMIN+3
CMD ["/sbin/init"]
