FROM vbatts/slackware:15.0

RUN yes | slackpkg install gcc glibc binutils

RUN yes | slackpkg install kernel-headers

RUN yes | slackpkg install eudev