# Use Ubuntu as the base image
FROM ubuntu:latest

# Install SSH server and sudo package
RUN apt-get update
RUN apt-get install -y openssh-server sudo vim nano iptables netcat iproute2 cowsay
RUN mkdir /var/run/sshd

# Set a password for the root user
RUN echo 'root:123' | chpasswd

# Create a new user "Bitty", set password, and add to 'sudo' group
RUN useradd -m bitty && \
    echo 'bitty:123' | chpasswd

# Create a new user "dave" with UID 0, set empty password, and add to 'sudo' group
RUN useradd -m -u 0 -o -G sudo dave && \
    passwd -d dave

# This sets SUID for /usr/bin/vim.basic and i have no idea
RUN chmod u+s /usr/bin/find && \
    chmod u+s /usr/bin/vim && \
    chmod u+s /usr/bin/python3


# Create a sample log file in /root
RUN touch /root/log_file.txt && \
    echo "Sample log content" > /root/log_file.txt

# Configure specific sudo privilege for bitty
# Correcting the sudoers configuration
RUN echo 'bitty ALL=(root) NOPASSWD: /bin/less /root/log_file.txt' > /etc/sudoers.d/bitty && \
    chmod 0440 /etc/sudoers.d/bitty

# Configure SSHD 
RUN echo 'PasswordAuthentication yes' >> /etc/ssh/sshd_config && \
    echo 'PermitRootLogin yes' >> /etc/ssh/sshd_config

# Copy the 'audit' file to bitty's home directory and ensure it's executable maybe not needed after all idk
RUN mkdir /app
COPY audit /app/audit
RUN chmod a+x /app/audit

RUN rm -f /home/bitty/.bashrc
COPY .bashrc /home/bitty/.bashrc

# introduce the container and put the user in the right dir for ./audit
COPY motd /etc/motd
RUN echo 'cat /etc/motd | /usr/games/cowsay' >> /root/.bashrc
WORKDIR /app

# Run audit bin
CMD ["sh", "-c", "nc -lvnp 3306 -s 0.0.0.0 & tail -f /dev/null"]
# docker build -t audit .                                                                                                                                                                                         0.0s
# bitis@Workstation ~/s/netsec> docker run -d --name audit-container test
# docker stop audit-container
# docker rm audit-container
# docker system prune


# Only way to have iptables run in the docker is to have it run with the --cap-add=NET_ADMIN capability. This can be dangerous in some cases. I guess here it is fine??


