#!/bin/bash -e
# ---
# RightScript Name: RL10 Test and Compile NSS
# Description: This is a sample script to compile/install the NSS plugin for RightScale.
#   It is meant for dev/test and as a reference mainly.
# Inputs:
#   BRANCH:
#     Category: Application
#     Description: Branch of libnss-rightlink to test
#     Input Type: single
#     Required: true
#     Advanced: false
#     Default: text:IV-1975_rightscale_nss
# Attachments: []
# ...

if which apt-get >/dev/null 2>&1; then
  if [ ! -e /tmp/apt-get-update-ran ]; then
    sudo apt-get update >/dev/null
    sudo touch /tmp/apt-get-update-ran
  fi
  sudo apt-get install -y build-essential autotools-dev autoconf automake libtool git
else
  echo "Only Ubuntu currently supported"
  exit 1
fi

cd ~
echo "Cloning NSS to $HOME/libnss-rightlink"
if [[ ! -e libnss-rightlink ]]; then 
  git clone http://github.com/rightscale/libnss-rightlink
fi
cd libnss-rightlink
git checkout -f $BRANCH

if [[ ! -e Makefile ]]; then
  ./bootstrap
  ./configure
fi
echo "Running make"
make
echo "Installing libnss_rightscale module"
sudo make install

if ! grep rightscale /etc/nsswitch.conf; then
  echo "Configuring /etc/nsswitch.conf"
  sudo sed -i -e '/^\(passwd\|group\|shadow\)/ s/$/ rightscale/' /etc/nsswitch.conf
else 
  echo "/etc/nsswitch.conf already configured"
fi

if [ -e /etc/pam.d/sshd ]; then
  if ! grep pam_mkhomedir /etc/pam.d/sshd; then
    echo "Adding pam_mkhomedir to /etc/pam.d/sshd"
    sudo bash -c "echo 'session    required    pam_mkhomedir.so skel=/etc/skel/ umask=0022' >> /etc/pam.d/sshd"
  else 
    echo "PAM config /etc/pam.d/sshd already contains pam_mkhomedir"
  fi
else
  echo "Don't know how to configure pam for this system!"
  exit 1
fi

if ! grep rs-ssh-keys /etc/ssh/sshd_config; then
  sudo sed -i -e '/AuthorizedKeysCommand\|AuthorizedKeysCommandUser/d' /etc/ssh/sshd_config
  echo "Adding AuthorizedKeysCommand /usr/local/bin/rs-ssh-keys to /etc/ssh/sshd_config"
  sudo bash -c "echo 'AuthorizedKeysCommand /usr/local/bin/rs-ssh-keys' >> /etc/ssh/sshd_config"
  sudo bash -c "echo 'AuthorizedKeysCommandUser nobody' >> /etc/ssh/sshd_config"
  sudo service ssh restart
else
  echo "AuthorizedKeysCommand already setup"
fi

echo "Writing out /usr/local/bin/rs-ssh-keys with +x"
sudo dd of="/usr/local/bin/rs-ssh-keys" 2>/dev/null <<EOF
#!/bin/bash

user=\$1

while IFS='' read -r line || [[ -n "\$line" ]]; do
  if [[ -z "\$line" ]] || [[ \$line =~ ^# ]]; then
    continue;
  fi
  preferred_name=\$(echo \$line | cut -d: -f1)
  unique_name=\$(echo \$line | cut -d: -f2)
  email=\$(echo \$line | cut -d: -f6)
  if [[ "\$preferred_name" == "\$user" ]] || [[ "\$unique_name" == "\$user" ]]; then
    echo "\$line" | cut -d: -f7- | tr : "\n"
  fi
done < /var/lib/rightlink/login_policy
exit 0
EOF
sudo chmod a+x /usr/local/bin/rs-ssh-keys

echo "Writing out /etc/sudoers.d/90-rightscale-users"
sudo dd of="/etc/sudoers.d/90-rightscale-users" 2>/dev/null <<EOF
%rightscale_sudo ALL=NOPASSWD: ALL
Defaults:%rightscale_sudo !requiretty
EOF

[[ -e /usr/local/bin/rsc ]] && rsc=/usr/local/bin/rsc || rsc=/opt/bin/rsc
$rsc --rl10 cm15 multi_add /api/tags/multi_add resource_hrefs[]=$RS_SELF_HREF tags[]=rs_login:state=user
