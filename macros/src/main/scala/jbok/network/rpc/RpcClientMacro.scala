package jbok.network.rpc

import scala.reflect.macros.blackbox

object RpcClientMacro {
  def useAPI[API: c.WeakTypeTag](c: blackbox.Context): c.Expr[API] = {
    import c.universe._

    val returnType: Type = weakTypeOf[API]

    val members: List[c.Tree] = createMembers[c.type, API](c)

    val expr = c.Expr[API] {
      q"""
        new $returnType {
          import _root_.io.circe.syntax._
          import _root_.io.circe.parser._
          import jbok.codec.json.implicits._
          import jbok.network.json._
          import cats.effect.IO
          import scala.scalajs.js.annotation.JSExport

          ..$members
        }
      """
    }

    expr
  }

  private def createMembers[CONTEXT <: blackbox.Context, API: c.WeakTypeTag](c: CONTEXT): List[c.Tree] = {
    import c.universe._
    val apiType: Type = weakTypeOf[API]
    MacroUtils[c.type](c)
      .getMembers(apiType)
      .map((member: Symbol) => createMember[c.type, API](c)(member))
  }

  private def createMember[CONTEXT <: blackbox.Context, API: c.WeakTypeTag](c: CONTEXT)(
      member: c.universe.Symbol): c.Tree = {
    import c.universe._

    val macroUtils           = MacroUtils[c.type](c)
    val method               = member.asMethod
    val methodName: TermName = method.name

    val request = {
      val parameterLists      = macroUtils.getParameterLists(method)
      val parametersAsTuple   = macroUtils.getParametersAsTuple(method)
      val parameterType: Tree = macroUtils.getParameterType(method)
      val resultType: Type    = method.returnType.typeArgs.head

      java.util.UUID.randomUUID().toString

      val body =
        q"""
          val request: JsonRpcRequest[$parameterType] =
            JsonRpcRequest[$parameterType](
              id = java.util.UUID.randomUUID().toString,
              method = ${methodName.toString},
              params = $parametersAsTuple
            )

          client.request(request.asJson.noSpaces).map(x => decode[JsonRpcResultResponse[$resultType]](x)).flatMap {
            case Left(e) => IO.raiseError(new Exception("parsing JsonRpcResponse failed"))
            case Right(x) => IO.pure(x.result)
          }
       """

      q"""
        @JSExport
        override def $methodName(...$parameterLists): IO[${resultType}] = {
          $body
        }
      """
    }
    request
  }
}
