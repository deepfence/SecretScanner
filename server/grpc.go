package server

import (
	"context"
	"fmt"
	"net"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/deepfence/SecretScanner/core"
	"github.com/deepfence/SecretScanner/output"
	"github.com/deepfence/SecretScanner/scan"
	pb "github.com/deepfence/agent-plugins-grpc/proto"
	"google.golang.org/grpc"
)

type gRPCServer struct {
	socket_path string
	plugin_name string
	pb.UnimplementedSecretScannerServer
	pb.UnimplementedAgentPluginServer
}

func (s *gRPCServer) GetName(context.Context, *pb.Empty) (*pb.Name, error) {
	return &pb.Name { Str: s.plugin_name }, nil
}

func (s *gRPCServer) GetUID(context.Context, *pb.Empty) (*pb.Uid, error) {
	return &pb.Uid { Str: fmt.Sprintf("%s-%s", s.plugin_name, s.socket_path) }, nil
}

func (s *gRPCServer) FindSecretInfo(_ context.Context, r *pb.FindRequest) (*pb.FindResult, error) {
	if r.GetPath()  != "" {
		var isFirstSecret bool = true
		var numSecrets uint = 0

		secrets, err := scan.ScanSecretsInDir("", r.GetPath(), r.GetPath(), &isFirstSecret, &numSecrets, nil)
		if err != nil {
			return nil, err
		}
		return &pb.FindResult{
			Timestamp: time.Now().String(),
			Secrets: output.SecretsToSecretInfos(secrets),
			Input: &pb.FindResult_Path{
				Path: r.GetPath(),
			},
		}, nil
	} else if r.GetImage() != nil && r.GetImage().Name != "" {
		res, err := scan.ExtractAndScanImage(r.GetImage().Name)
		if err != nil {
			return nil, err
		}

		return &pb.FindResult{
			Timestamp: time.Now().String(),
			Secrets: output.SecretsToSecretInfos(res.Secrets),
			Input: &pb.FindResult_Image{
				Image: &pb.DockerImage{
					Name: r.GetImage().Name,
					Id: res.ImageId,
				},
			},
		}, nil
	} else if r.GetContainer() != nil && r.GetContainer().Id != "" {
		res, err := scan.ExtractAndScanContainer(r.GetContainer().Id, r.GetContainer().Namespace)
		if err != nil {
			return nil, err
		}

		return &pb.FindResult{
			Timestamp: time.Now().String(),
			Secrets: output.SecretsToSecretInfos(res.Secrets),
			Input: &pb.FindResult_Container{
				Container: &pb.Container{
					Namespace: r.GetContainer().Namespace,
					Id: res.ContainerId,
				},
			},
		}, nil
	}
	return nil, fmt.Errorf("Invalid request")
}

func RunServer(socket_path string, plugin_name string) error {

	sigs := make(chan os.Signal, 1)
	done := make(chan bool, 1)

	signal.Notify(sigs, syscall.SIGINT, syscall.SIGTERM)

	lis, err := net.Listen("unix", fmt.Sprintf("%s", socket_path))
	if err != nil {
		return err
	}
	s := grpc.NewServer()

	go func() {
		<-sigs
		s.GracefulStop()
		done <- true
	}()

	impl := &gRPCServer{socket_path: socket_path, plugin_name: plugin_name}
	pb.RegisterAgentPluginServer(s, impl)
	pb.RegisterSecretScannerServer(s, impl)
	core.GetSession().Log.Info("main: server listening at %v", lis.Addr())
	if err := s.Serve(lis); err != nil {
		return err
	}

	<-done
	core.GetSession().Log.Info("main: exiting gracefully")
	return nil
}
