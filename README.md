# Android Library Hiding

This repository contains the code and images for my dive into exploring the ways actors may hide their shared-libraries and how a defender may work against them.

The write-up for this repository is located at: [android-library-hiding](https://lovy.sh/posts/android-library-hiding/)

Repository contents

Directory | Contents
| ---- | ----
attack/ | Contains the source for an attacker library-set.
defend/ | Contains the code for the detections.
test_app/ | Test Environment.

The repository contains code for basic detections and techniques to load libraries obscurely, including via android manual-mapping, although it purposefully does not contain a complete implementation of this technique.
