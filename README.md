# audit.go - Audit Exercise for Network Security Course

Intended as a simple exercise for the course 02233 Network Security at DTU.

Students simply pull and run the Docker image from Docker Hub, allowing them to focus on learning and completing the relevant tasks without the hassle of setup.

## Description (for students)

Having impressed the recruiter as well as the hiring-manager, you've successfully landed a job at **BigCorp**<sup>**TM**</sup>. Congratulations!

It is not long however, before your new boss informs you why you were needed so urgently. Turns out they fired their old
Linux systems administrator for incompetence, and you've been tasked with cleaning up their mess!

You ask your new boss for more information, and they mutter something about ssh and "dangerous permissions".
However, when pressed for more information they simply shrug and tell you to figure it out. That's why they pay you the big bucks after all.

## Instructions (for students)

To pull the image run:
`docker pull bitisg/audit:latest`

To run the image run the command:
`docker run -d --name audit-container --cap-add=NET_ADMIN bitisg/audit:latest`

* `-d` runs the container in detached mode (in the background).
* `--name audit-container` gives the container a name (audit-container), making it easier to refer to.
* `--cap-add=NET_ADMIN` This grants the container some additional network-related privileges.
* `bitisg/audit:latest` specifies the image to run.

To enter the container run:
`docker exec -it audit-container /bin/bash`

To check your progress run the `audit` binary located on the system. There are multiple things for you to fix, and some can be a bit tricky if you aren't totally familiar with
Linux. If you get stuck, run the binary with the `--hints` flag to get hints for the levels you haven't solved.

## Troubleshooting

If you break the image for whatever reason you can stop and remove the container using `docker stop audit-container` and `docker rm audit-container`

You can then pull and run the image as described in the **Instructions** section.

## Expected Outcomes

By completing this exercise, students will gain experience with:

- Navigating and troubleshooting common issues in a Linux environment.
- Understanding and fixing permission-related security issues.
- Applying best practices for network security configurations.
