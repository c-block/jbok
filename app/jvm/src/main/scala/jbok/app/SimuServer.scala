package jbok.app

import java.net.InetSocketAddress
import java.security.SecureRandom

import better.files.File
import cats.effect.IO
import jbok.app.simulations.{SimulationAPI, SimulationImpl}
import jbok.common.execution._
import jbok.core.keystore.KeyStorePlatform
import jbok.network.rpc.RpcServer
import jbok.network.rpc.RpcServer._
import jbok.network.server.Server

import scala.concurrent.duration._
import scala.io.StdIn

object SimuServer {
  val bind = new InetSocketAddress("localhost", 8888)

  // keystore
  val secureRandom = new SecureRandom()
  val dir          = File.newTemporaryDirectory().deleteOnExit()
  val keyStore     = KeyStorePlatform[IO](dir.pathAsString, secureRandom).unsafeRunSync()

  val impl: SimulationAPI = SimulationImpl().unsafeRunSync()
  val rpcServer           = RpcServer().unsafeRunSync().mountAPI[SimulationAPI](impl)
  val server              = Server.websocket(bind, rpcServer.pipe)
  val peerCount           = 10
  val minerCount          = 1

  val init = for {
    _ <- impl.createNodesWithMiner(peerCount, minerCount)
    _ <- impl.startNetwork
    _ <- impl.connect("ring")
    _ = T.sleep(5000.millis)
    _ <- impl.submitStxsToNetwork(10, "valid")
  } yield ()

  def main(args: Array[String]): Unit = {
    init.unsafeRunSync()
    val fiber = server.stream.compile.drain.start.unsafeRunSync()
    println("simulation start")

    println(s"server listen on ${bind}, press any key to quit")
    StdIn.readLine()

    println("stop simulation")
    val cleanUp = for {
      _ <- impl.stopNetwork
    } yield ()
    cleanUp.unsafeRunSync()

    fiber.cancel.unsafeRunSync()
  }
}
