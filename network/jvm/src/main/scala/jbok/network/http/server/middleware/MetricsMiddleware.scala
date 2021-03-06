package jbok.network.http.server.middleware

import cats.effect.{Clock, Effect, Sync}
import cats.implicits._
import jbok.common.metrics.PrometheusMetrics
import org.http4s.HttpRoutes
import org.http4s.metrics.prometheus.{Prometheus, PrometheusExportService}
import org.http4s.server.middleware

object MetricsMiddleware {
  def exportService[F[_]](implicit F: Sync[F]): F[HttpRoutes[F]] =
    for {
      _ <- PrometheusExportService.addDefaults[F](PrometheusMetrics.registry)
    } yield PrometheusExportService.service[F](PrometheusMetrics.registry)

  def apply[F[_]](routes: HttpRoutes[F], enableMetrics: Boolean)(implicit F: Effect[F], clock: Clock[F]): F[HttpRoutes[F]] =
    if (enableMetrics) {
      Prometheus[F](PrometheusMetrics.registry, "jbok_http_server").map { metricsOps =>
        middleware.Metrics[F](metricsOps)(routes)
      }
    } else {
      F.pure(routes)
    }
}
