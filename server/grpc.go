package server

import (
	"context"

	"github.com/deepfence/SecretScanner/jobs"
	"github.com/deepfence/SecretScanner/output"
	out "github.com/deepfence/YaraHunter/pkg/output"
	"github.com/deepfence/YaraHunter/pkg/server"
	pb "github.com/deepfence/agent-plugins-grpc/srcgo"
	"github.com/sirupsen/logrus"
	//nolint:typecheck
)

type SecretGRPCServer struct {
	*server.GRPCScannerServer
	pb.UnimplementedSecretScannerServer
}

func (s *SecretGRPCServer) FindSecretInfo(c context.Context, r *pb.FindRequest) (*pb.FindResult, error) {
	yaraScanner, err := s.YaraRules.NewScanner()
	if err != nil {
		return &pb.FindResult{}, err
	}

	go func() {
		logrus.Infof("request to scan %+v", r)

		namespace := ""
		container := ""
		image := ""
		path := ""
		switch {
		case r.GetContainer() != nil:
			namespace = r.GetContainer().GetNamespace()
			container = r.GetContainer().GetId()
		case r.GetImage() != nil:
			image = r.GetImage().GetName()
		default:
			path = r.GetPath()
		}

		server.DoScan(
			r.ScanId,
			s.HostMountPath,
			s.ExtractorConfig,
			s.InactiveThreshold,
			&s.ScanMap,
			namespace,
			path,
			image,
			container,
			yaraScanner,
			func(res out.IOCFound, scanID string) {
				for i := range res.StringsToMatch {
					jobs.WriteSingleScanData(output.SecretToSecretInfo(res, i), scanID)
				}
			},
		)
	}()
	return &pb.FindResult{}, nil
}
