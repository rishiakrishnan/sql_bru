library(rpart)
age <- c(22, 24, 30, 35, 45, 50, 60, 65, 70, 75, 80, 85) 
survived <- as.factor(c(0, 0, 0, 1, 1, 0, 1, 0, 1, 1, 0, 0)) 
data <- data.frame(Age = age, Survived = survived)
model <- rpart(Survived ~ Age, data = data, method = "class", control = rpart.control(minsplit = 1))

plot(model, uniform = TRUE, margin = 0.1)
text(model, use.n = TRUE, cex = 0.8)
print(model)