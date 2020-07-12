#!/usr/bin/env Rscript
# clean-up session parameters
rm(list=ls())

# load data
my.path <- paste0(getwd(), "/")
# example
# load.data <- read.csv(paste0(my.path, file.name), header=TRUE)

# set seed
set.seed(12345)

# load libraries
libs <- c("ggplot2")
for(i in 1:length(libs)) {
    pkg <- sprintf("%s", libs[i])
    print(sprintf("load %s", pkg))
    suppressMessages(library(pkg, character.only = TRUE))
}

df=read.csv("perf.csv", header=T)
# use data of two replicas
# ndf=subset(df, df$replicas==2)
ggplot(df, aes(x=test, y=rps, fill=server)) + geom_bar(position="dodge", stat="identity") + labs(x = "test (n-calls/concurrent clients)", y = "Requests/sec")
ggsave("perf-rps2.pdf")
ggplot(df, aes(x=test, y=100*(failures/(failures+responses)), fill=server)) + geom_bar(position="dodge", stat="identity") + labs(x = "test (n-calls/concurrent clients)", y = "failure rate (%)")
ggsave("perf-failure2.pdf")
