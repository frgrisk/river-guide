# River-Guide

[![Go Report Card](https://goreportcard.com/badge/github.com/frgrisk/river-guide)](https://goreportcard.com/report/github.com/frgrisk/river-guide)

River-Guide is a simple web interface for managing AWS EC2 instances. It
utilizes the AWS SDK for Go and provides features like listing EC2 instances
and starting/stopping instances through a web interface. River-Guide also
supports tag-based filtering of instances, enabling you to only display
instances of interest. Configuration can be provided through command line
flags, a configuration file, or environment variables.

## Prerequisites

To use River-Guide, you'll need to have:

- [Go](https://golang.org/dl/) installed on your local machine.
- AWS credentials configured on your local machine. You can configure it
  using AWS CLI by running `aws configure`.
- The permission to start and stop instances.

## Installation

You can use the [pre-built binaries](https://github.com/frgrisk/river-guide/releases).

```bash
curl -L https://github.com/frgrisk/river-guide/releases/download/v0.2.0/river-guide-linux-amd64 --output /opt/river-guide
chmod 755 /opt/river-guide
```

or you can install it using go

```bash
go install github.com/frgrisk/river-guide@latest
```

## Usage

To start the server, use the following command:

```bash
river-guide
```

### Flags

The application accepts several flags:

- `--config`: path to configuration file (default is `$HOME/.river-guide.yaml`).
- `-p, --port`: port to listen on (default is `3000`).
- `--path-prefix`: path prefix for the application (default is `/`).
- `--provider`: cloud provider to use (default is `aws`).
- `--resource-group-name`: name of the resource group to use (required for
  Azure).
- `--subscription-id`: subscription ID to use (required for Azure).
- `-t, --tags`: filter instances using tag key-value pairs (e.g.,
  `Environment=dev,Name=dev.example.com`).
- `--title`: title to display on the web page (default is "Environment
  Control").
- `--primary-color`: primary color for text (default is "#333").
- `--favicon`: path to favicon (default is embedded favicon).

### Configuration file

The application can also use a configuration file for setting the parameters.
The configuration file should be in the YAML format. By default, the
application will look for a `.river-guide.yaml` file in the home directory.
The structure of the file should look something like this:

```yaml
port: 3000
tags:
  Environment: dev
  Name: dev.example.com
title: Environment Control
primary-color: "#333"
favicon: "/path/to/favicon"
```

### Environment variables

In addition to flags and the configuration file, you can also use
environment variables to set parameters. The application will automatically
look for any environment variables beginning with `RIVER_GUIDE_`. For
instance, to set the title, you could use the following command:

```bash
export RIVER_GUIDE_TITLE="My Custom Title"
```

## API

The application provides the following endpoints:

- `GET /`: The main interface for managing AWS EC2 instances.
- `GET /favicon.ico`: Endpoint for serving favicon.
- `POST /toggle`: Endpoint for toggling the start/stop state of all instances.

## To Do

- [ ] Add error handling for AWS API calls.

## License

River Guide is released under the MIT License. See the [LICENSE](./LICENSE)
file for more details.
