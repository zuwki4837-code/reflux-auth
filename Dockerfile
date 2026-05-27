FROM mcr.microsoft.com/dotnet/sdk:9.0 AS build
WORKDIR /src
COPY ["RefluxAuth.csproj", "./"]
RUN dotnet restore "RefluxAuth.csproj"
COPY . .
RUN dotnet publish "RefluxAuth.csproj" -c Release -o /app/publish

FROM mcr.microsoft.com/dotnet/aspnet:9.0
WORKDIR /app
COPY --from=build /app/publish .
RUN mkdir -p /app/data
ENV DATABASE_DIR=/app/data
ENV DOTNET_EnableDiagnostics=0
EXPOSE 8080
ENTRYPOINT ["dotnet", "RefluxAuth.dll"]
