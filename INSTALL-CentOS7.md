# Installation instructions for CentOS 7

## Assumptions
server.example.com __(ELK master)__

client.example.com __(client machine)__

## ELK Stack installation on server.example.com
###### Install Java 8
```
yum install -y java-1.8.0-openjdk
```
###### Import PGP Key
```
rpm --import https://artifacts.elastic.co/GPG-KEY-elasticsearch
```
###### Create Yum repository
```
cat >>/etc/yum.repos.d/elk.repo<<EOF
[elasticsearch]
name=Elasticsearch repository for 7.x packages
baseurl=https://artifacts.elastic.co/packages/7.x/yum
gpgcheck=1
gpgkey=https://artifacts.elastic.co/GPG-KEY-elasticsearch
enabled=1
autorefresh=1
type=rpm-md
EOF
```
### Elasticsearch
###### Install Elasticsearch
```
yum install -y elasticsearch
```

###### Enable and start elasticsearch service
```
systemctl daemon-reload
systemctl enable elasticsearch
systemctl start elasticsearch
```


###### Configure security


add to /etc/elasticsearch/elasticsearch.yml

```
xpack.security.enabled: true
```

and restart

```
systemctl restart elasticsearch
```

Configure built-in users, take note of kibana and elastic credentials, in this case 

- `kibana`:`elasticpassword`
- `elastic`:`elasticpassword`

```
/usr/share/elasticsearch/bin/elasticsearch-setup-passwords interactive
```

###### Create initial SuperUser

```
curl -X POST "elastic:elasticpassword@localhost:9200/_security/user/luis?pretty" -H 'Content-Type: application/json' -d'
{
  "password" : "chacon",
  "roles" : [ "superuser" ]
}
'
```

### Kibana
###### Install kibana
```
yum install -y kibana
```

###### Configure kibana Auth

Update the following settings in the `/etc/kibana.yml` configuration file:
```
elasticsearch.username: "kibana"
elasticsearch.password: "elasticpassword"

xpack.security.encryptionKey: "something_at_least_32_characters"
```

###### Enable and start kibana service
```
systemctl daemon-reload
systemctl enable kibana
systemctl start kibana
```
###### Install Nginx
```
yum install -y epel-release
yum install -y nginx
```
###### Create Proxy configuration
Remove server block from the default config file /etc/nginx/nginx.conf
And create a new config file
```
cat >>/etc/nginx/conf.d/kibana.conf<<EOF
server {
    listen 80;
    server_name server.example.com;
    location / {
        proxy_pass http://localhost:5601;
    }
}
EOF
```
###### Selinux allowance
```
 sudo setsebool httpd_can_network_connect 1 -P
```

###### Enable and start nginx service
```
systemctl enable nginx
systemctl start nginx
```
### Logstash
###### Install logstash
```
yum install -y logstash
```
###### Generate SSL Certificates
```
openssl req -subj '/CN=server.example.com/' -x509 -days 3650 -nodes -batch -newkey rsa:2048 -keyout /etc/pki/tls/private/logstash.key -out /etc/pki/tls/certs/logstash.crt
```
###### Create Logstash config file
```
vi /etc/logstash/conf.d/01-logstash-simple.conf
```
Paste the below content
```
input {
  beats {
    port => 5044
    ssl => true
    ssl_certificate => "/etc/pki/tls/certs/logstash.crt"
    ssl_key => "/etc/pki/tls/private/logstash.key"
  }
}

filter {
    if [type] == "syslog" {
        grok {
            match => {
                "message" => "%{SYSLOGTIMESTAMP:syslog_timestamp} %{SYSLOGHOST:syslog_hostname} %{DATA:syslog_program}(?:\[%{POSINT:syslog_pid}\])?: %{GREEDYDATA:syslog_message}"
            }
            add_field => [ "received_at", "%{@timestamp}" ]
            add_field => [ "received_from", "%{host}" ]
        }
        syslog_pri { }
        date {
            match => [ "syslog_timestamp", "MMM  d HH:mm:ss", "MMM dd HH:mm:ss" ]
        }
    }
}

output {
    elasticsearch {
        hosts => "localhost:9200"
        index => "%{[@metadata][beat]}-%{+YYYY.MM.dd}"
    }
}
```
###### Enable and Start logstash service
```
systemctl enable logstash
systemctl start logstash
```
## FileBeat installation on client.example.com
###### Create Yum repository
```
cat >>/etc/yum.repos.d/elk.repo<<EOF
[ELK-6.x]
name=ELK repository for 6.x packages
baseurl=https://artifacts.elastic.co/packages/6.x/yum
gpgcheck=1
gpgkey=https://artifacts.elastic.co/GPG-KEY-elasticsearch
enabled=1
autorefresh=1
type=rpm-md
EOF
```
###### Install Filebeat
```
yum install -y filebeat
```
###### Copy SSL certificate from server.example.com
```
scp server.example.com:/etc/pki/tls/certs/logstash.crt /etc/pki/tls/certs/
```
###### Configure Filebeat 

- Set `enable` to true
- add:

  paths:
    - /var/log/messages
    - /var/log/secure
    - /var/log/nginx/*.log
    
 - comment output.elasticsearch:
 - configure output.logstash
 - remember the certificate /etc/pki/tls/certs/logstash.crt

###### Enable and start Filebeat service
```
systemctl enable filebeat
systemctl start filebeat
```


### Fluentd

###### Preparation
```
yum -y install make automake gcc gcc-c++ kernel-devel patch libyaml-devel libffi-devel glibc-headers autoconf glibc-devel readline-devel zlib-devel openssl-devel bzip2 libtool bison
```

###### Ruby via ruby version manager
```
#ruby version manager

gpg2 --keyserver hkp://keys.gnupg.net --recv-keys D39DC0E3
sudo gpg2 --keyserver hkp://pool.sks-keyservers.net --recv-keys 409B6B1796C275462A1703113804BB82D39DC0E3 7D2BAF1CF37B13E2069D6956105BD0E739499BDB
curl -sSL https://rvm.io/mpapis.asc | sudo gpg2 --import -
curl -sSL https://rvm.io/pkuczynski.asc | sudo gpg2 --import -
    
curl -L get.rvm.io | bash -s stable
source /etc/profile.d/rvm.sh
rvm install 2.6.0
gem install fluentd
```

###### Fluentd itself

```
curl -L https://toolbelt.treasuredata.com/sh/install-redhat-td-agent3.sh | sh
td-agent-gem update

systemctl enable td-agent
systemctl start td-agent

# fluent elasticsearch plugin
td-agent-gem install fluent-plugin-nostat
td-agent-gem install fluent-plugin-elasticsearch
```

Add config

```
<match nginx.*>
  @type elasticsearch
  host localhost
  port 9200
  logstash_format true
  user logstash_system
  password elasticpassword
  index_name testing_logs
</match>

<source>
  @type tail
  path /var/log/nginx/access.log
  pos_file /var/log/td-agent/nginx-access.log.pos
  tag nginx.access #fluentd tag!
  format nginx
</source>

<source>
  @type nostat
  run_interval 1
  mode dstat # raw or dstat
  output_type graphite # hash or graphite
</source>
```


### Configure Kibana Dashboard
All done. Now you can head to Kibana dashboard and add the index.


