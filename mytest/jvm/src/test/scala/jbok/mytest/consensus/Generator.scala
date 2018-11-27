package jbok.mytest.consensus

trait Generator[+T] {
  self=>
  def generate:T
  def map[U](f:T=>U)=new Generator[U] {
     def generate=f(self.generate)
  }
  def flatMap[U](f:T=>Generator[U])=new Generator[U] {
    def generate=f(self.generate).generate
  }
}
object Generator{
  //integers 只是表示 有能力 调用generate时生成 一个integers
  val integers=new Generator[Int] {
    override def generate: Int = {
      val rand=new java.util.Random
      rand.nextInt()
    }
  }
  def single[T](x:T)=new Generator[T] {
    def generate=x
  }
  val booleans=for{ x<- integers }yield x>0
  def pairs[T,U](a:Generator[T],b:Generator[U])=for{
    x1<-a
    x2<-b
  }yield (x1,x2)
  def lists:Generator[List[Int]]=for {
    isEmpty <-booleans
    list <- if(isEmpty) emptyList else nonEmptyList
  }yield list

  def emptyList=single(Nil)

  def nonEmptyList=for{
    head<-integers
    tail<-lists
  } yield (head::tail)

  def test[T](g:Generator[T],numTimes:Int=100)(test:T=>Boolean)={
    for(i <-0 until numTimes){
      val value=g.generate
      assert(test(value),"test failed for value "+value)
    }
    print("passed "+ numTimes +"test")
  }
  test(pairs(lists,lists)){
    case(x1,x2)=>(x1++x2).length > x1.length
  }
}

