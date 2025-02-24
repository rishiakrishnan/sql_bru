data(iris)
set.seed(123)
kmeans_model <- kmeans(iris[, -5], centers = 3)
plot(iris$Sepal.Length, iris$Sepal.Width, col = kmeans_model$cluster,
     pch = 19, xlab = "Sepal Length", ylab = "Sepal Width", 
     main = "K-Means Clustering")
