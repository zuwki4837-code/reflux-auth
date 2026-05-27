FROM mcr.microsoft.com/dotnet/sdk:9.0 AS build
WORKDIR /src
COPY ["RefluxAuth.csproj", "./"]
RUN dotnet restore "RefluxAuth.csproj"
COPY . .
WORKDIR "/src/"
RUN dotnet build "RefluxAuth.csproj" -c Release -o /app/build

FROM build AS publish
RUN dotnet publish "RefluxAuth.csproj" -c Release -o /app/publish

FROM mcr.microsoft.com/dotnet/aspnet:9.0 AS base
USER root
WORKDIR /app
EXPOSE 8080
COPY --from=publish /app/publish .

# Set up writable database folder and fix permissions for secure app user
RUN mkdir -p /app/data && chown -R 1654:1654 /app /app/data

USER app
ENV DATABASE_DIR=/app/data
ENV PORT=8080
ENV ASPNETCORE_URLS=http://+:8080

ENTRYPOINT ["dotnet", "RefluxAuth.dll"]
