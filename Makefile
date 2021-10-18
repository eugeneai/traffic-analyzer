.PHONY: all tests st itests gt igt t i transform run irun

LGT=LOGTALKHOME=/usr/lib/logtalk/share/logtalk swilgt

run: transform

run:
	$(LGT) -g "{pkt_loader},halt."

irun:
	$(LGT) -g "{pkt_loader},logtalk_load(tools(loader))."
